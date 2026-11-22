
import logging
import stripe

from django.http import HttpResponse
from django.conf import settings
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

from checkout.webhook_handler import StripeWH_Handler


logger = logging.getLogger(__name__)


@require_POST
@csrf_exempt
def webhook(request):
    """Listen for webhooks from Stripe"""

    # Setup
    wh_secret = settings.STRIPE_WH_SECRET
    stripe.api_key = settings.STRIPE_SECRET_KEY

    # Get the webhook data and verify its signature
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, wh_secret
        )

    except ValueError as e:
        logger.exception("Invalid Stripe webhook payload")
        return HttpResponse(
            content=f'Invalid payload: {e}',
            status=400
        )

    except stripe.SignatureVerificationError as e:
        logger.exception("Stripe webhook signature verification failed")
        return HttpResponse(
            content=f'Signature verification failed: {e}',
            status=400
        )

    except Exception as e:
        logger.exception("Error verifying Stripe webhook")
        return HttpResponse(content=str(e), status=400)

    # Set up a webhook handler
    handler = StripeWH_Handler(request)

    event_map = {
        'payment_intent.succeeded':
            handler.handle_payment_intent_succeeded,
        'payment_intent.payment_failed':
            handler.handle_payment_intent_payment_failed,
    }

    event_type = event['type']
    event_handler = event_map.get(
        event_type, handler.handle_event
    )

    try:
        response = event_handler(event)
        return response

    except Exception:
        logger.exception(
            "Error processing Stripe webhook event: %s", event_type
        )
        return HttpResponse(
            content='Webhook processing failed',
            status=500
        )
