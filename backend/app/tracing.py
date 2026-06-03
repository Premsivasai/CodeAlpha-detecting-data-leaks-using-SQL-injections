from app.config import settings
import logging

logger = logging.getLogger(__name__)

tracer = None
trace_provider = None


def init_tracing():
    global tracer, trace_provider
    
    if not settings.OPENTELEMETRY_ENABLED:
        logger.info("OpenTelemetry tracing disabled")
        return
    
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        
        resource = Resource.create({
            SERVICE_NAME: settings.OPENTELEMETRY_SERVICE_NAME,
            "service.version": settings.VERSION,
            "deployment.environment": settings.SENTRY_ENVIRONMENT
        })
        
        trace_provider = TracerProvider(resource=resource)
        
        otlp_exporter = OTLPSpanExporter(
            endpoint=settings.OPENTELEMETRY_ENDPOINT,
            insecure=True
        )
        
        trace_provider.add_span_processor(
            BatchSpanProcessor(otlp_exporter)
        )
        
        trace.set_tracer_provider(trace_provider)
        tracer = trace.get_tracer(__name__)
        
        logger.info(f"OpenTelemetry initialized: {settings.OPENTELEMETRY_SERVICE_NAME}")
        
    except Exception as e:
        logger.warning(f"Failed to initialize OpenTelemetry: {e}")


def get_tracer():
    global tracer
    if tracer is None:
        init_tracing()
    return tracer


def trace_span(name: str, attributes: dict = None):
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            current_tracer = get_tracer()
            if current_tracer:
                with current_tracer.start_as_current_span(name) as span:
                    if attributes:
                        for key, value in attributes.items():
                            span.set_attribute(key, str(value))
                    try:
                        result = await func(*args, **kwargs)
                        span.set_attribute("success", True)
                        return result
                    except Exception as e:
                        span.set_attribute("success", False)
                        span.set_attribute("error", str(e))
                        raise
            return await func(*args, **kwargs)
        
        def sync_wrapper(*args, **kwargs):
            current_tracer = get_tracer()
            if current_tracer:
                with current_tracer.start_as_current_span(name) as span:
                    if attributes:
                        for key, value in attributes.items():
                            span.set_attribute(key, str(value))
                    try:
                        result = func(*args, **kwargs)
                        span.set_attribute("success", True)
                        return result
                    except Exception as e:
                        span.set_attribute("success", False)
                        span.set_attribute("error", str(e))
                        raise
            return func(*args, **kwargs)
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


class DistributedTracing:
    def __init__(self):
        self.tracer = get_tracer()
    
    def start_span(self, name: str, **attributes):
        if self.tracer:
            return self.tracer.start_span(name, attributes=attributes)
        return None
    
    def add_event(self, span, event_name: str, **attributes):
        if span:
            span.add_event(event_name, attributes=attributes)
    
    def set_attribute(self, span, key: str, value):
        if span:
            span.set_attribute(key, value)
    
    def end_span(self, span):
        if span:
            span.end()


tracing_service = DistributedTracing()