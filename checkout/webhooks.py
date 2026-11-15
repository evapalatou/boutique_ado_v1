
from django.http import HttpResponse
from django.conf import settings
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

from checkout.webhook_handler import StripeWH_Handler

import stripe


@require_POST
@csrf_exempt
def webhook(request):
    """Listen for webhooks from Stripe"""

    # Setup
    wh_secret = settings.STRIPE_WH_SECRET
    stripe.api_key = settings.STRIPE_SECRET_KEY
    stripe_client = stripe.StripeClient(settings.STRIPE_SECRET_KEY)

    # Get the webhook data and verify its signature
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

    try:
        notification = stripe_client.parse_event_notification(
            payload, sig_header, wh_secret
        )

    except ValueError:
        # Invalid payload
        return HttpResponse(status=400)

    except stripe.error.SignatureVerificationError:
        # Invalid signature
        return HttpResponse(status=400)

    except Exception as e:
        return HttpResponse(content=str(e), status=400)

    # Set up a webhook handler
    handler = StripeWH_Handler(request)

    # Get the webhook type from Stripe
    event_type = notification.type

    # Map thin webhook events to relevant handler functions
    if event_type == 'v1.payment_intent.succeeded':
        intent = notification.fetch_related_object()
        response = handler.handle_payment_intent_succeeded(
            intent, event_type
        )

    elif event_type == 'v1.payment_intent.payment_failed':
        response = handler.handle_payment_intent_payment_failed(
            event_type
        )

    else:
        response = handler.handle_event(event_type)

    return response
