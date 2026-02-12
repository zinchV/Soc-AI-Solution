"""
Auto-Triage System
Automatically triggers triage analysis based on configurable conditions.
"""
import os
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Callable, Awaitable
from enum import Enum
from dotenv import load_dotenv

load_dotenv()


class TriggerType(Enum):
    """Types of auto-triage triggers"""
    COUNT_THRESHOLD = "count_threshold"     # Trigger after N alerts
    CRITICAL_ALERT = "critical_alert"       # Trigger on critical severity
    TIME_BASED = "time_based"               # Trigger every N minutes
    MANUAL = "manual"                       # Manual trigger only


class AutoTriageConfig:
    """Configuration for auto-triage system"""
    
    def __init__(self):
        # Alert count threshold
        self.count_threshold = int(os.getenv("AUTO_TRIAGE_COUNT_THRESHOLD", "50"))
        
        # Time-based interval (minutes)
        self.time_interval_minutes = int(os.getenv("AUTO_TRIAGE_INTERVAL_MINUTES", "15"))
        
        # Trigger on critical alerts
        self.trigger_on_critical = os.getenv("AUTO_TRIAGE_ON_CRITICAL", "true").lower() == "true"
        
        # Enable auto-triage
        self.enabled = os.getenv("AUTO_TRIAGE_ENABLED", "true").lower() == "true"
        
        # Cooldown period (seconds) - prevent too frequent triggers
        self.cooldown_seconds = int(os.getenv("AUTO_TRIAGE_COOLDOWN", "300"))


class AutoTriageManager:
    """
    Manages automatic triage triggering based on various conditions.
    """
    
    def __init__(self, triage_callback: Callable[[], Awaitable[dict]] = None):
        """
        Initialize the auto-triage manager.
        
        Args:
            triage_callback: Async function to call when triage is triggered
        """
        self.config = AutoTriageConfig()
        self.triage_callback = triage_callback
        
        # State tracking
        self.alerts_since_last_triage = 0
        self.last_triage_time: Optional[datetime] = None
        self.triage_in_progress = False
        
        # Background task for time-based triggers
        self._time_based_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            "total_triggers": 0,
            "count_triggers": 0,
            "critical_triggers": 0,
            "time_triggers": 0,
            "manual_triggers": 0,
            "last_trigger_type": None,
            "last_trigger_time": None
        }
    
    def set_triage_callback(self, callback: Callable[[], Awaitable[dict]]):
        """Set the callback function for triage execution"""
        self.triage_callback = callback
    
    async def on_alert_ingested(self, alert: dict) -> Optional[dict]:
        """
        Called when a new alert is ingested.
        Checks if auto-triage should be triggered.
        
        Args:
            alert: The ingested alert
        
        Returns:
            Triage result if triggered, None otherwise
        """
        if not self.config.enabled:
            return None
        
        self.alerts_since_last_triage += 1
        
        # Check critical alert trigger
        if self.config.trigger_on_critical and alert.get("severity") == "Critical":
            if await self._can_trigger():
                print(f"🚨 Auto-triage triggered: Critical alert received")
                return await self._execute_triage(TriggerType.CRITICAL_ALERT)
        
        # Check count threshold trigger
        if self.alerts_since_last_triage >= self.config.count_threshold:
            if await self._can_trigger():
                print(f"📊 Auto-triage triggered: Count threshold ({self.config.count_threshold}) reached")
                return await self._execute_triage(TriggerType.COUNT_THRESHOLD)
        
        return None
    
    async def on_batch_ingested(self, alerts: list) -> Optional[dict]:
        """
        Called when a batch of alerts is ingested.
        
        Args:
            alerts: List of ingested alerts
        
        Returns:
            Triage result if triggered, None otherwise
        """
        if not self.config.enabled:
            return None
        
        self.alerts_since_last_triage += len(alerts)
        
        # Check for critical alerts in batch
        if self.config.trigger_on_critical:
            critical_alerts = [a for a in alerts if a.get("severity") == "Critical"]
            if critical_alerts and await self._can_trigger():
                print(f"🚨 Auto-triage triggered: {len(critical_alerts)} critical alerts in batch")
                return await self._execute_triage(TriggerType.CRITICAL_ALERT)
        
        # Check count threshold
        if self.alerts_since_last_triage >= self.config.count_threshold:
            if await self._can_trigger():
                print(f"📊 Auto-triage triggered: Count threshold ({self.config.count_threshold}) reached")
                return await self._execute_triage(TriggerType.COUNT_THRESHOLD)
        
        return None
    
    async def trigger_manual(self) -> dict:
        """
        Manually trigger triage analysis.
        
        Returns:
            Triage result
        """
        print("👆 Manual triage triggered")
        return await self._execute_triage(TriggerType.MANUAL)
    
    async def start_time_based_triggers(self):
        """Start background task for time-based triggers"""
        if not self.config.enabled:
            return
        
        if self._time_based_task and not self._time_based_task.done():
            return  # Already running
        
        self._time_based_task = asyncio.create_task(self._time_based_loop())
        print(f"⏰ Time-based auto-triage started (interval: {self.config.time_interval_minutes} minutes)")
    
    async def stop_time_based_triggers(self):
        """Stop background task for time-based triggers"""
        if self._time_based_task:
            self._time_based_task.cancel()
            try:
                await self._time_based_task
            except asyncio.CancelledError:
                pass
            self._time_based_task = None
            print("⏰ Time-based auto-triage stopped")
    
    async def _time_based_loop(self):
        """Background loop for time-based triggers"""
        interval_seconds = self.config.time_interval_minutes * 60
        
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                
                # Only trigger if there are new alerts since last triage
                if self.alerts_since_last_triage > 0:
                    if await self._can_trigger():
                        print(f"⏰ Auto-triage triggered: Time interval ({self.config.time_interval_minutes} min)")
                        await self._execute_triage(TriggerType.TIME_BASED)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Error in time-based triage loop: {e}")
                await asyncio.sleep(60)  # Wait a bit before retrying
    
    async def _can_trigger(self) -> bool:
        """Check if triage can be triggered (cooldown check)"""
        if self.triage_in_progress:
            return False
        
        if self.last_triage_time:
            elapsed = (datetime.utcnow() - self.last_triage_time).total_seconds()
            if elapsed < self.config.cooldown_seconds:
                return False
        
        return True
    
    async def _execute_triage(self, trigger_type: TriggerType) -> dict:
        """Execute triage analysis"""
        if not self.triage_callback:
            return {"error": "No triage callback configured"}
        
        self.triage_in_progress = True
        
        try:
            result = await self.triage_callback()
            
            # Update state
            self.last_triage_time = datetime.utcnow()
            self.alerts_since_last_triage = 0
            
            # Update stats
            self.stats["total_triggers"] += 1
            self.stats["last_trigger_type"] = trigger_type.value
            self.stats["last_trigger_time"] = self.last_triage_time.isoformat()
            
            if trigger_type == TriggerType.COUNT_THRESHOLD:
                self.stats["count_triggers"] += 1
            elif trigger_type == TriggerType.CRITICAL_ALERT:
                self.stats["critical_triggers"] += 1
            elif trigger_type == TriggerType.TIME_BASED:
                self.stats["time_triggers"] += 1
            elif trigger_type == TriggerType.MANUAL:
                self.stats["manual_triggers"] += 1
            
            return result
            
        except Exception as e:
            print(f"❌ Error during auto-triage: {e}")
            return {"error": str(e)}
        finally:
            self.triage_in_progress = False
    
    def get_status(self) -> dict:
        """Get current status of auto-triage system"""
        return {
            "enabled": self.config.enabled,
            "config": {
                "count_threshold": self.config.count_threshold,
                "time_interval_minutes": self.config.time_interval_minutes,
                "trigger_on_critical": self.config.trigger_on_critical,
                "cooldown_seconds": self.config.cooldown_seconds
            },
            "state": {
                "alerts_since_last_triage": self.alerts_since_last_triage,
                "last_triage_time": self.last_triage_time.isoformat() if self.last_triage_time else None,
                "triage_in_progress": self.triage_in_progress,
                "time_based_running": self._time_based_task is not None and not self._time_based_task.done()
            },
            "stats": self.stats
        }
    
    def update_config(
        self,
        enabled: bool = None,
        count_threshold: int = None,
        time_interval_minutes: int = None,
        trigger_on_critical: bool = None,
        cooldown_seconds: int = None
    ):
        """Update auto-triage configuration"""
        if enabled is not None:
            self.config.enabled = enabled
        if count_threshold is not None:
            self.config.count_threshold = count_threshold
        if time_interval_minutes is not None:
            self.config.time_interval_minutes = time_interval_minutes
        if trigger_on_critical is not None:
            self.config.trigger_on_critical = trigger_on_critical
        if cooldown_seconds is not None:
            self.config.cooldown_seconds = cooldown_seconds


# Global instance
auto_triage_manager = AutoTriageManager()
