from app.config import settings
import logging
import json
from typing import Optional, Dict, Any, Callable
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, list] = {}
        self._kafka_producer = None
        self._rabbitmq_channel = None
    
    async def publish(self, event_type: str, payload: Dict[str, Any], tenant_id: Optional[int] = None):
        event = {
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "tenant_id": tenant_id,
            "payload": payload
        }
        
        await self._publish_to_kafka(event_type, event)
        await self._publish_to_rabbitmq(event_type, event)
        await self._publish_to_subscribers(event_type, event)
    
    async def _publish_to_kafka(self, event_type: str, event: Dict):
        if not settings.KAFKA_BOOTSTRAP_SERVERS:
            return
        
        try:
            from kafka import KafkaProducer
            from kafka.errors import NoBrokersAvailable
            
            if self._kafka_producer is None:
                try:
                    self._kafka_producer = KafkaProducer(
                        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                        key_serializer=lambda k: k.encode('utf-8') if k else None,
                        security_protocol=settings.KAFKA_SECURITY_PROTOCOL
                    )
                except NoBrokersAvailable:
                    logger.warning("Kafka broker not available")
                    return
            
            topic = f"secureshield.{event_type}"
            key = str(event.get("tenant_id", "global"))
            self._kafka_producer.send(topic, key=key, value=event)
            self._kafka_producer.flush()
            
        except Exception as e:
            logger.warning(f"Kafka publish failed: {e}")
    
    async def _publish_to_rabbitmq(self, event_type: str, event: Dict):
        if not settings.RABBITMQ_URL:
            return
        
        try:
            import aio_pika
            
            if self._rabbitmq_channel is None:
                connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
                self._rabbitmq_channel = await connection.channel()
            
            exchange = await self._rabbitmq_channel.declare_exchange(
                "secureshield_events",
                aio_pika.ExchangeType.TOPIC,
                durable=True
            )
            
            routing_key = f"events.{event_type}"
            message = aio_pika.Message(
                body=json.dumps(event).encode(),
                content_type="application/json",
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT
            )
            
            await exchange.publish(message, routing_key=routing_key)
            
        except Exception as e:
            logger.warning(f"RabbitMQ publish failed: {e}")
    
    async def _publish_to_subscribers(self, event_type: str, event: Dict):
        subscribers = self._subscribers.get(event_type, [])
        for callback in subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Subscriber callback failed: {e}")
    
    def subscribe(self, event_type: str, callback: Callable):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def unsubscribe(self, event_type: str, callback: Callable):
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type] if cb != callback
            ]
    
    async def close(self):
        if self._kafka_producer:
            self._kafka_producer.close()
        if self._rabbitmq_channel:
            await self._rabbitmq_channel.close()


event_bus = EventBus()


class EventTypes:
    ATTACK_DETECTED = "attack.detected"
    ATTACK_BLOCKED = "attack.blocked"
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_REGISTRATION = "user.registration"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_RESOLVED = "incident.resolved"
    ALERT_GENERATED = "alert.generated"
    THREAT_INTEL_UPDATED = "threat_intel.updated"
    API_CALL = "api.call"
    BILLING_USAGE = "billing.usage"


async def emit_attack_event(attack_data: Dict, tenant_id: Optional[int] = None):
    await event_bus.publish(
        EventTypes.ATTACK_DETECTED,
        {
            "attack_id": attack_data.get("id"),
            "ip_address": attack_data.get("ip_address"),
            "attack_type": attack_data.get("attack_type"),
            "severity": attack_data.get("severity"),
            "payload": attack_data.get("payload", "")[:200],
            "blocked": attack_data.get("blocked", True)
        },
        tenant_id
    )


async def emit_incident_event(incident_data: Dict, tenant_id: Optional[int] = None):
    await event_bus.publish(
        EventTypes.INCIDENT_CREATED,
        incident_data,
        tenant_id
    )


async def emit_user_event(event_type: str, user_data: Dict, tenant_id: Optional[int] = None):
    await event_bus.publish(
        event_type,
        user_data,
        tenant_id
    )


async def emit_api_event(api_data: Dict, tenant_id: Optional[int] = None):
    await event_bus.publish(
        EventTypes.API_CALL,
        api_data,
        tenant_id
    )