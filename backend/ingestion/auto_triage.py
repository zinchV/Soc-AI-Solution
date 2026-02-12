"""
Auto-Triage Manager
Automatically triggers AI triage when alerts are ingested.
Triggers on EVERY alert (Low, Medium, High, Critical).
"""
import asyncio
import os
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum


class TriageMode(Enum):
    """Triage trigger modes"""
    IMMEDIATE = "immediate"      # Triage on every alert
    BATCHED = "batched"          # Triage after X alerts
    SCHEDULED = "scheduled"      # Triage on time interval


class AutoTriageManager:
    """
    Manages automatic triage triggering.
    Default mode: IMMEDIATE - triggers on every alert.
    """
    
    def __init__(self):
        # Configuration from environment or defaults
        self.enabled = os.getenv("AUTO_TRIAGE_ENABLED", "true").lower() == "true"
        self.mode = TriageMode.IMMEDIATE  # Always immediate now
        
        # Batch settings (for future use if needed)
        self.batch_threshold = int(os.getenv("AUTO_TRIAGE_BATCH_SIZE", "5"))
        
        # Debounce settings - prevents multiple rapid triages
        self.debounce_seconds = int(os.getenv("AUTO_TRIAGE_DEBOUNCE", "30"))
        
        # State tracking
        self.pending_alerts = 0
        self.last_triage_time: Optional[datetime] = None
        self.triage_in_progress = False
        self.total_triages = 0
        self.total_alerts_processed = 0
        
        # Callback function (set by router)
        self._triage_callback = None
        
        # Background task
        self._debounce_task: Optional[asyncio.Task] = None
        
    def set_triage_callback(self, callback):
        """Set the callback function to execute triage"""
        self._triage_callback = callback
        
    def get_status(self) -> Dict[str, Any]:
        """Get current auto-triage status"""
        return {
            "enabled": self.enabled,
            "mode": self.mode.value,
            "config": {
                "debounce_seconds": self.debounce_seconds,
                "batch_threshold": self.batch_threshold
            },
            "state": {
                "pending_alerts": self.pending_alerts,
                "triage_in_progress": self.triage_in_progress,
                "last_triage": self.last_triage_time.isoformat() if self.last_triage_time else None
            },
            "stats": {
                "total_triages": self.total_triages,
                "total_alerts_processed": self.total_alerts_processed
            }
        }
    
    async def on_alert_received(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Called when a new alert is received.
        Triggers triage based on configuration.
        
        Returns status of the triage trigger.
        """
        if not self.enabled:
            return {"triggered": False, "reason": "auto_triage_disabled"}
        
        self.pending_alerts += 1
        severity = alert.get("severity", "Medium")
        
        print(f"📥 Alert received: {severity} - {alert.get('description', 'No description')[:50]}")
        
        # Check if we should trigger triage
        should_trigger = await self._should_trigger(alert)
        
        if should_trigger:
            # Use debounced triage to batch rapid alerts
            result = await self._debounced_triage()
            return {"triggered": True, "result": result}
        
        return {
            "triggered": False,
            "reason": "debounce_active",
            "pending_alerts": self.pending_alerts
        }
    
    async def _should_trigger(self, alert: Dict[str, Any]) -> bool:
        """Determine if triage should be triggered"""
        
        # Don't trigger if already in progress
        if self.triage_in_progress:
            return False
        
        # Always trigger for Critical alerts immediately
        if alert.get("severity") == "Critical":
            print("⚡ Critical alert - immediate triage")
            return True
        
        # For other severities, use debounced approach
        # This batches rapid alerts together
        return True
    
    async def _debounced_triage(self) -> Optional[Dict[str, Any]]:
        """
        Debounced triage - waits a short period to batch rapid alerts.
        If multiple alerts come in within debounce window, only one triage runs.
        """
        # Cancel existing debounce task if any
        if self._debounce_task and not self._debounce_task.done():
            # Already have a pending triage, don't start another
            return {"status": "pending", "message": "Triage already scheduled"}
        
        # Schedule triage after short delay to batch rapid alerts
        self._debounce_task = asyncio.create_task(self._delayed_triage())
        
        try:
            return await self._debounce_task
        except asyncio.CancelledError:
            return {"status": "cancelled"}
    
    async def _delayed_triage(self) -> Dict[str, Any]:
        """Execute triage after a short delay"""
        # Short delay to batch rapid alerts (3 seconds)
        await asyncio.sleep(3)
        
        return await self._execute_triage()
    
    async def _execute_triage(self) -> Dict[str, Any]:
        """Execute the actual triage"""
        if self.triage_in_progress:
            return {"status": "skipped", "reason": "triage_in_progress"}
        
        if not self._triage_callback:
            return {"status": "error", "reason": "no_callback_configured"}
        
        self.triage_in_progress = True
        alerts_to_process = self.pending_alerts
        
        print(f"\n🤖 AUTO-TRIAGE TRIGGERED")
        print(f"   Processing {alerts_to_process} pending alert(s)...")
        
        try:
            # Call the triage function
            result = await self._triage_callback()
            
            # Update stats
            self.total_triages += 1
            self.total_alerts_processed += alerts_to_process
            self.pending_alerts = 0
            self.last_triage_time = datetime.now()
            
            print(f"✅ Auto-triage complete")
            
            return {
                "status": "success",
                "alerts_processed": alerts_to_process,
                "result": result
            }
            
        except Exception as e:
            print(f"❌ Auto-triage error: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
        finally:
            self.triage_in_progress = False
    
    async def trigger_manual(self) -> Dict[str, Any]:
        """Manually trigger triage"""
        print("👆 Manual triage triggered")
        return await self._execute_triage()
    
    async def start_time_based_triggers(self):
        """Start background time-based triage (optional cleanup)"""
        if not self.enabled:
            return
        
        async def periodic_check():
            interval = 300  # 5 minutes
            while True:
                await asyncio.sleep(interval)
                
                # Only run if there are pending alerts and no recent triage
                if self.pending_alerts > 0 and not self.triage_in_progress:
                    time_since_last = None
                    if self.last_triage_time:
                        time_since_last = (datetime.now() - self.last_triage_time).seconds
                    
                    # Run cleanup triage if it's been more than 5 minutes
                    if time_since_last is None or time_since_last > interval:
                        print("⏰ Time-based triage check")
                        await self._execute_triage()
        
        # Start background task
        asyncio.create_task(periodic_check())
        print("⏰ Background triage monitor started (5 min cleanup interval)")


# Global instance
auto_triage_manager = AutoTriageManager()
