from app.config import settings
import logging
import json
import asyncio
from typing import Dict, Any

logger = logging.getLogger(__name__)


class EventConsumer:
    def __init__(self):
        self._running = False
        self._kafka_consumer = None
        self._rabbitmq_connection = None
    
    async def start(self):
        self._running = True
        asyncio.create_task(self._consume_kafka())
        asyncio.create_task(self._consume_rabbitmq())
    
    async def stop(self):
        self._running = False
        if self._kafka_consumer:
            self._kafka_consumer.close()
        if self._rabbitmq_connection:
            await self._rabbitmq_connection.close()
    
    async def _consume_kafka(self):
        if not settings.KAFKA_BOOTSTRAP_SERVERS:
            return
        
        try:
            from kafka import KafkaConsumer
            
            self._kafka_consumer = KafkaConsumer(
                "secureshield.attack.detected",
                "secureshield.incident.created",
                "secureshield.alert.generated",
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                auto_offset_reset='latest',
                enable_auto_commit=True,
                security_protocol=settings.KAFKA_SECURITY_PROTOCOL
            )
            
            logger.info("Kafka consumer started")
            
            for message in self._kafka_consumer:
                if not self._running:
                    break
                
                try:
                    await self._handle_event(message.value)
                except Exception as e:
                    logger.error(f"Kafka event handling error: {e}")
                    
        except Exception as e:
            logger.warning(f"Kafka consumer failed: {e}")
    
    async def _consume_rabbitmq(self):
        if not settings.RABBITMQ_URL:
            return
        
        try:
            import aio_pika
            
            self._rabbitmq_connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
            channel = await self._rabbitmq_connection.channel()
            
            queue = await channel.declare_queue("secureshield_events", durable=True)
            
            logger.info("RabbitMQ consumer started")
            
            async with queue.iterator() as queue_iter:
                async for message in queue_iter:
                    if not self._running:
                        break
                    
                    async with message.process():
                        try:
                            event = json.loads(message.body.decode())
                            await self._handle_event(event)
                        except Exception as e:
                            logger.error(f"RabbitMQ event handling error: {e}")
                            
        except Exception as e:
            logger.warning(f"RabbitMQ consumer failed: {e}")
    
    async def _handle_event(self, event: Dict[str, Any]):
        event_type = event.get("type")
        payload = event.get("payload", {})
        tenant_id = event.get("tenant_id")
        
        logger.debug(f"Processing event: {event_type}")
        
        if event_type == "attack.detected":
            await self._handle_attack_event(payload, tenant_id)
        elif event_type == "incident.created":
            await self._handle_incident_event(payload, tenant_id)
        elif event_type == "alert.generated":
            await self._handle_alert_event(payload, tenant_id)
    
    async def _handle_attack_event(self, payload: Dict, tenant_id: int):
        from app.logs import alert_service
        from app.database import AsyncSessionLocal
        
        async with AsyncSessionLocal() as db:
            await alert_service.create_alert(
                db,
                alert_type="attack",
                severity=payload.get("severity", "medium"),
                title=f"Attack Detected: {payload.get('attack_type')}",
                message=f"Attack from {payload.get('ip_address')}",
                meta=payload,
                tenant_id=tenant_id
            )
    
    async def _handle_incident_event(self, payload: Dict, tenant_id: int):
        logger.info(f"Incident created: {payload.get('id')}")
    
    async def _handle_alert_event(self, payload: Dict, tenant_id: int):
        logger.info(f"Alert generated: {payload.get('title')}")


event_consumer = EventConsumer()