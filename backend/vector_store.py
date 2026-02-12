"""
Vector store using ChromaDB with semantic embeddings.
Supports both local sentence-transformers and Gemini embeddings.
Uses cosine similarity for semantic search.
"""
import os
import pathlib
import chromadb
from chromadb.config import Settings
from typing import List, Dict, Any, Optional
import json
import httpx
from dotenv import load_dotenv

load_dotenv()

# Configuration
BASE_DIR = pathlib.Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
CHROMA_DIR = DATA_DIR / "chromadb"
CHROMA_DIR.mkdir(parents=True, exist_ok=True)

# Choose embedding provider: "default" (sentence-transformers) or "gemini"
EMBEDDING_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "gemini")


class GeminiEmbeddingFunction:
    """Custom embedding function using Gemini's text-embedding-004 model"""
    
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = "text-embedding-004"
        #self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.base_url = "https://generativelanguage.googleapis.com/v1/models"
        self._dimension = 768
    
    def name(self) -> str:
        """Return the name of this embedding function (required by ChromaDB)"""
        return "gemini-text-embedding-004"
    
    def __call__(self, input: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts (used for indexing)"""
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not configured for embeddings")
        
        if not input:
            return []
        
        embeddings = []
        batch_size = 100
        
        for i in range(0, len(input), batch_size):
            batch = input[i:i + batch_size]
            batch_embeddings = self._embed_batch(batch)
            embeddings.extend(batch_embeddings)
        
        return embeddings
    
    def embed_query(self, input: str = None, query: str = None, text: str = None) -> List[float]:
        """Generate embedding for a single query (used for searching)"""
        # Accept any parameter name ChromaDB might use
        query_text = input or query or text
        if not query_text:
            return [0.0] * self._dimension
        
        embeddings = self._embed_batch([query_text])
        return embeddings[0]
    
    def _embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed a batch of texts using Gemini API"""
        url = f"{self.base_url}/{self.model}:batchEmbedContents?key={self.api_key}"
        
        # Format requests for batch embedding
        requests = []
        for text in texts:
            requests.append({
                "model": f"models/{self.model}",
                "content": {
                    "parts": [{"text": str(text)}]
                },
                "taskType": "RETRIEVAL_DOCUMENT"
            })
        
        payload = {"requests": requests}
        
        try:
            with httpx.Client(timeout=60.0, verify=False) as client:
                response = client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code != 200:
                    print(f"Gemini embedding error: {response.text}")
                    return [[0.0] * self._dimension for _ in texts]
                
                data = response.json()
                
                if "embeddings" not in data:
                    print(f"Embedding error: 'embeddings' not in response")
                    return [[0.0] * self._dimension for _ in texts]
                
                embeddings = [
                    item["values"] for item in data["embeddings"]
                ]
                return embeddings
                
        except Exception as e:
            print(f"Embedding exception: {e}")
            return [[0.0] * self._dimension for _ in texts]


class VectorStore:
    def __init__(self):
        # Initialize ChromaDB with persistent storage
        self.client = chromadb.PersistentClient(
            path=str(CHROMA_DIR),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Set up embedding function based on configuration
        self.embedding_function = self._get_embedding_function()
        
        # Create or get collections with COSINE similarity
        self.alerts_collection = self.client.get_or_create_collection(
            name="security_alerts",
            embedding_function=self.embedding_function,
            metadata={
                "description": "Security alerts for SOC analysis",
                "hnsw:space": "cosine"
            }
        )
        
        self.incidents_collection = self.client.get_or_create_collection(
            name="security_incidents",
            embedding_function=self.embedding_function,
            metadata={
                "description": "Correlated security incidents",
                "hnsw:space": "cosine"
            }
        )
        
        print(f"✅ ChromaDB initialized with {EMBEDDING_PROVIDER} embeddings")
        print(f"   Alerts indexed: {self.alerts_collection.count()}")
        print(f"   Incidents indexed: {self.incidents_collection.count()}")
    
    def _get_embedding_function(self):
        """Get the appropriate embedding function based on configuration"""
        if EMBEDDING_PROVIDER == "gemini":
            print("Using Gemini text-embedding-004 for embeddings")
            return GeminiEmbeddingFunction()
        else:
            # Use ChromaDB's default (sentence-transformers/all-MiniLM-L6-v2)
            print("Using default sentence-transformers embeddings (all-MiniLM-L6-v2)")
            return None  # ChromaDB uses default when None
    
    def add_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        """Add alerts to the vector store with semantic embeddings"""
        if not alerts:
            return 0
        
        documents = []
        metadatas = []
        ids = []
        
        for alert in alerts:
            alert_id = str(alert.get("id", ""))
            
            # Create rich text document for embedding
            doc_text = f"""
Security Alert - {alert.get('severity', 'Unknown')} Severity
Event Type: {alert.get('event_type', 'Unknown')}
Source IP: {alert.get('source_ip', 'Unknown')}
Destination IP: {alert.get('destination_ip', 'Unknown')}
User: {alert.get('user', 'Unknown')}
Description: {alert.get('description', '')}
Timestamp: {alert.get('timestamp', '')}
            """.strip()
            
            documents.append(doc_text)
            metadatas.append({
                "alert_id": alert_id,
                "severity": alert.get('severity', 'Unknown'),
                "event_type": alert.get('event_type', 'Unknown'),
                "source_ip": alert.get('source_ip', ''),
                "destination_ip": alert.get('destination_ip', ''),
                "user": alert.get('user', ''),
                "timestamp": str(alert.get('timestamp', ''))
            })
            ids.append(f"alert_{alert_id}")
        
        # Upsert to handle duplicates
        self.alerts_collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        return len(alerts)
    
    def search_alerts(self, query: str, n_results: int = 20, 
                      severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Semantic search for alerts using cosine similarity"""
        if self.alerts_collection.count() == 0:
            return []
        
        # Build where filter if severity specified
        where_filter = None
        if severity_filter:
            where_filter = {"severity": severity_filter}
        
        try:
            # Manually generate embedding for Gemini
            if self.embedding_function:
                query_embedding = self.embedding_function.embed_query(input=query)
                results = self.alerts_collection.query(
                    query_embeddings=[query_embedding],
                    n_results=min(n_results, self.alerts_collection.count()),
                    where=where_filter,
                    include=["documents", "metadatas", "distances"]
                )
            else:
                # Use query_texts for default embedding function
                results = self.alerts_collection.query(
                    query_texts=[query],
                    n_results=min(n_results, self.alerts_collection.count()),
                    where=where_filter,
                    include=["documents", "metadatas", "distances"]
                )
            
            # Format results
            formatted_results = []
            if results and results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    # Cosine distance to similarity (cosine distance is 0-2, similarity is 1-distance)
                    distance = results['distances'][0][i] if results['distances'] else 0
                    similarity = 1 - distance  # For cosine: similarity = 1 - distance
                    
                    formatted_results.append({
                        "document": doc,
                        "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                        "relevance_score": round(max(0, similarity), 3)  # Ensure non-negative
                    })
            
            return formatted_results
            
        except Exception as e:
            print(f"Search error: {e}")
            return []
    
    def add_incidents(self, incidents: List[Dict[str, Any]]) -> int:
        """Add incidents to the vector store"""
        if not incidents:
            return 0
        
        documents = []
        metadatas = []
        ids = []
        
        for incident in incidents:
            incident_id = str(incident.get("id", ""))
            
            doc_text = f"""
Security Incident: {incident.get('title', '')}
Summary: {incident.get('summary', '')}
Severity: {incident.get('severity', 'Unknown')}
Status: {incident.get('status', 'active')}
Attack Stage: {incident.get('attack_stage', 'Unknown')}
Alert Count: {incident.get('alert_count', 0)}
Confidence: {incident.get('confidence', 0)}
            """.strip()
            
            documents.append(doc_text)
            metadatas.append({
                "incident_id": incident_id,
                "severity": incident.get('severity', 'Unknown'),
                "status": incident.get('status', 'active'),
                "attack_stage": incident.get('attack_stage', ''),
                "alert_count": str(incident.get('alert_count', 0)),
                "confidence": str(incident.get('confidence', 0))
            })
            ids.append(f"incident_{incident_id}")
        
        self.incidents_collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        return len(incidents)
    
    def search_incidents(self, query: str, n_results: int = 10,
                        status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Semantic search for incidents using cosine similarity"""
        if self.incidents_collection.count() == 0:
            return []
        
        where_filter = None
        if status_filter:
            where_filter = {"status": status_filter}
        
        try:
            # Manually generate embedding for Gemini
            if self.embedding_function:
                query_embedding = self.embedding_function.embed_query(input=query)
                results = self.incidents_collection.query(
                    query_embeddings=[query_embedding],
                    n_results=min(n_results, self.incidents_collection.count()),
                    where=where_filter,
                    include=["documents", "metadatas", "distances"]
                )
            else:
                # Use query_texts for default embedding function
                results = self.incidents_collection.query(
                    query_texts=[query],
                    n_results=min(n_results, self.incidents_collection.count()),
                    where=where_filter,
                    include=["documents", "metadatas", "distances"]
                )
            
            formatted_results = []
            if results and results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    # Cosine distance to similarity
                    distance = results['distances'][0][i] if results['distances'] else 0
                    similarity = 1 - distance
                    
                    formatted_results.append({
                        "document": doc,
                        "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                        "relevance_score": round(max(0, similarity), 3)
                    })
            
            return formatted_results
            
        except Exception as e:
            print(f"Incident search error: {e}")
            return []
    
    def get_similar_alerts(self, alert_id: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find alerts similar to a specific alert"""
        try:
            # Get the alert document
            result = self.alerts_collection.get(
                ids=[f"alert_{alert_id}"],
                include=["documents"]
            )
            
            if not result['documents']:
                return []
            
            # Search for similar alerts
            return self.search_alerts(result['documents'][0], n_results + 1)[1:]  # Exclude self
            
        except Exception as e:
            print(f"Similar alerts error: {e}")
            return []
    
    def get_stats(self) -> Dict[str, int]:
        """Get collection statistics"""
        return {
            "alerts_indexed": self.alerts_collection.count(),
            "incidents_indexed": self.incidents_collection.count(),
            "embedding_provider": EMBEDDING_PROVIDER
        }
    
    def clear_all(self):
        """Clear all data from collections - Windows compatible"""
        try:
            alerts_data = self.alerts_collection.get()
            if alerts_data and alerts_data['ids']:
                self.alerts_collection.delete(ids=alerts_data['ids'])
        except Exception as e:
            print(f"Warning: Could not clear alerts collection: {e}")
        
        try:
            incidents_data = self.incidents_collection.get()
            if incidents_data and incidents_data['ids']:
                self.incidents_collection.delete(ids=incidents_data['ids'])
        except Exception as e:
            print(f"Warning: Could not clear incidents collection: {e}")
        
        print("✅ All vector store data cleared")


# Global instance
vector_store = VectorStore()
