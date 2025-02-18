from .models import (User, NewsletterSubscription, ContactMessage, PasswordReset)
from .forms import (NewsletterSubscriptionForm, CustomUserChangeForm, ContactMessageForm, PasswordResetForm, CustomUserCreationForm, ResetPasswordForm, ResetPasswordConfirmForm) 
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, views as auth_views, get_user_model
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import render, redirect
from django.core.mail import EmailMessage
from django.core.mail import send_mail
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.urls import reverse, reverse_lazy
from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
#from django.utils.encoding import force_text
from django.shortcuts import render, redirect, get_object_or_404
from django.core.cache import cache
from django.utils.translation import gettext_lazy as _
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To
from sendgrid.helpers.mail import *
from django.contrib.auth.decorators import login_required
import requests
from requests.exceptions import RequestException
import json
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import os
import stripe
from django.core.validators import validate_email
from django.core.exceptions import ValidationError


SENDGRID_API_KEY = settings.SENDGRID_API_KEY
DEFAULT_FROM_EMAIL = settings.DEFAULT_FROM_EMAIL  
def send_email_via_sendgrid(request, to_email, template_id, dynamic_template_data):
    sg = SendGridAPIClient(api_key=SENDGRID_API_KEY)
    from_email=Email(DEFAULT_FROM_EMAIL)
    to_email = To(to_email)
    message = Mail(from_email, to_email)
    
    message.template_id = template_id
    message.dynamic_template_data = dynamic_template_data
    try:
        response = sg.client.mail.send.post(request_body=message.get())
    
        if response.status_code != 202:  # Not accepted or queued by SendGrid
            logger.error(f"Failed to send email, response: {response}")
            messages.error(request, 'There was an error and the password reset could not be completed.')
    except Exception as e:
        logger.error(f"SendGrid email send failure: {e}", exc_info=True)
        messages.error(request, 'There was an error and the password reset could not be completed.')

# Create your views here.

def index(request):
    if request.method == 'POST':
        form = NewsletterSubscriptionForm(request.POST or None)
        if form.is_valid():
            try:
                validate_email(form.cleaned_data['Email'])
            except ValidationError:
                form.add_error('Email', 'Invalid email address')
                messages.error(request, 'Invalid email address')
                return render(request, 'contact.html', {'form': form})
            newsletter_sub = form.save()
            Email = newsletter_sub.Email
            protocol = 'https' if request.is_secure() else 'http'  # Use 'http' for local development
            checkout_link = f"{protocol}://{request.get_host()}/checkout/"
            logger.info(f"Checkout link: {checkout_link}")

            dynamic_template_data = {'checkout_link': checkout_link} #{{checkout_link}}
            # Send email using SendGrid
            send_email_via_sendgrid(
                request,
                to_email=Email,
                template_id='d-8e6191bb9eb04684ab82ef38a7ce6113',
                dynamic_template_data=dynamic_template_data
            )
            messages.success(request, 'Thank you for joining our newsletter!')
            return HttpResponseRedirect(reverse('index') + '#bottom')
        else:
            if form.has_error('Email', code='unique'):
                messages.error(request, 'The email you entered is already subscribed to our newsletter.')
                return HttpResponseRedirect(reverse('index') + '#bottom')
            elif form.has_error('Email', code='invalid'):
                messages.error(request, 'Please enter a valid email address.')
                return HttpResponseRedirect(reverse('index') + '#bottom')
            else:
                messages.error(request, 'There was an error with your submission.')
                return render(request, 'index.html', {'form': form})
    else:
        form = NewsletterSubscriptionForm()
        return render(request, 'index.html', {'form': form})

def about(request):
    return render(request, 'about.html')

def contact(request):
    if request.method == 'POST':
        form = ContactMessageForm(request.POST or None)
        if form.is_valid():
            # Validate email
            try:
                validate_email(form.cleaned_data['Email'])
            except ValidationError:
                form.add_error('Email', 'Invalid email address')
                messages.error(request, 'Invalid email address')
                return render(request, 'contact.html', {'form': form})

            # Validate phone number
            phone_number = form.cleaned_data['PhoneNumber']
            phone_number = ''.join(filter(str.isdigit, phone_number))  # Remove non-numeric characters
            if len(phone_number) != 10:  # Check if phone number has 10 digits
                form.add_error('PhoneNumber', 'Invalid phone number')
                messages.error(request, 'Invalid phone number')
                return render(request, 'contact.html', {'form': form})

            # Validate message length
            message = form.cleaned_data['Message']
            if len(message) > 200:  # Check if message length exceeds 250 characters
                form.add_error('Message', 'Message must be a maximum of 250 characters')
                messages.error(request, 'Max 250 characters')
                return render(request, 'contact.html', {'form': form})
            
            # If email and phone number are valid, continue with form processing
            contact_message = form.save()
            Email = contact_message.Email
            protocol = 'https' if request.is_secure() else 'http'
            checkout_link = f"{protocol}://{request.get_host()}/checkout/"
            dynamic_template_data = {'checkout_link': checkout_link} #{{checkout_link}}
            # Send email to user using SendGrid
            send_email_via_sendgrid(
                request,
                to_email=Email,
                template_id='d-aca65f653797425fa3b857983365edd1',
                dynamic_template_data=dynamic_template_data
            )
            # Send email to me using SendGrid
            dynamic_template_data_info = {
                'FullName': contact_message.FullName,
                'Email': contact_message.Email,
                'Subject': contact_message.Subject,
                'Message': contact_message.Message,
                'PhoneNumber': contact_message.PhoneNumber
            }
            send_email_via_sendgrid(
                request,
                to_email='info@etchedn.com',
                template_id='d-261eeb82f3a34fc0aaeb864217662cb2',  # Replace with your template ID
                dynamic_template_data=dynamic_template_data_info
            )
            messages.success(request, 'Your message was successfully submitted!')
            return redirect('contact')
        else:
            messages.error(request, 'There was an error with your submission.')
            return render(request, 'contact.html', {'form': form})
    else:
        form = ContactMessageForm()
    return render(request, 'contact.html', {'form': form})

def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            # Validate phone number
            phone_number = form.cleaned_data.get('PhoneNumber', '')
            phone_number = ''.join(filter(str.isdigit, phone_number))  # Remove non-numeric characters
            if len(phone_number) != 10:  # Check if phone number has 10 digits
                form.add_error('PhoneNumber', 'Invalid phone number')
                messages.error(request, 'Invalid phone number')
                return render(request, 'signup.html', {'form': form})  # Ensure this is the correct template for errors
            
            try:
                validate_email(form.cleaned_data['email'])
            except ValidationError:
                form.add_error('email', 'Invalid email address')
                messages.error(request, 'Invalid email address')
                return render(request, 'contact.html', {'form': form})
            user = form.save(commit=False)
            user.username = form.cleaned_data.get('username')
            user.first_name = form.cleaned_data.get('first_name')
            user.email = form.cleaned_data.get('email')
            user.save()
            protocol = 'https' if request.is_secure() else 'http'
            checkout_link = f"{protocol}://{request.get_host()}/checkout/"
            dynamic_template_data = {'checkout_link': checkout_link, 'first_name': user.first_name}
            # Send email using SendGrid
            send_email_via_sendgrid(
                request,
                to_email=user.email,
                template_id='d-9ed90303c0814ef3aac3fb00d3284f7f',
                dynamic_template_data=dynamic_template_data
            )
            messages.success(request, 'You have successfully signed up!')
            return redirect('login')
        else:
            print("Form errors:", form.errors)
            if form.has_error('email', code='unique'):
                messages.error(request, 'The email you entered is already attached to an account.')
                return render(request, 'signup.html', {'form': form})
            else:
                messages.error(request, 'There was an error registering your account.')
                return render(request, 'signup.html', {'form': form})
    else:
        form = CustomUserCreationForm()
    return render(request, 'signup.html', {'form': form})

def login_user(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('username') #this is actually the email not the username
            password = form.cleaned_data.get('password')

            logger.info(f"Attempting to log in with email: {email}")
            logger.warning(f"Failed login attempt for email: {email}")
            user = authenticate(request, username=email, password=password)
            if user is not None:
                auth_login(request, user)
                #messages.success(request, 'You have successfully logged in!')
                return redirect('dashboard_home')
            else:
                logger.warning(f"Failed login attempt for email: {email}")
                messages.error(request, 'Invalid email or password.')
                return render(request, 'login.html', {'form': form})
        else:
            logger.error(f"Form invalid: {form.errors}")
            logger.debug(f"POST data: {request.POST}")
            messages.error(request, 'Invalid email or password.')
            return render(request, 'login.html', {'form': form})
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

def logout(request):
    logout(request)
    return redirect('index')


def reset_password_request(request):
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            user = User.objects.filter(email=email).first()
            if user:
                # Generate token
                token = default_token_generator.make_token(user)
                # Encode UID
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                # Create the password reset link
                #PRODUCTION
                protocol = 'https' if request.is_secure() else 'http'  # Use 'http' for local development
                password_reset_link = f"{protocol}://{request.get_host()}/reset_password_confirm/{uidb64}/{token}/"
                logger.info(f"Password reset link: {password_reset_link}")
                logger.info(f"Generated token: {token}")
                logger.info(f"Generated uidb64: {uidb64}")
                # Set up dynamic data for SendGrid
                dynamic_template_data = {'password_reset_link': password_reset_link}
                # Send email using SendGrid
                send_email_via_sendgrid(
                    request,
                    to_email=email,
                    template_id='d-0f48f6ad814c4a22be95dbc0c862126e',
                    dynamic_template_data=dynamic_template_data
                )
                # Check for message tags in the template to display the success/error message.
                messages.success(request, 'An email has been sent with instructions on how to reset your password.')
                return redirect('reset_password_request') if not messages.get_messages(request) else redirect('reset_password_request')
            else:
                messages.error(request, 'Something went wrong while resetting your password.')
                return redirect('reset_password_request')
        else:
            messages.error(request, 'There is no account registered with the specified email address!')
            return render(request, 'reset_password_request.html', {'form': form})
    else:
        form = ResetPasswordForm()
        return render(request, 'reset_password_request.html', {'form': form})


#INPUT NEW PASSWORD AND CONFIRM IT
def reset_password_confirm(request, uidb64, token):
    # Decode UID and get user
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        messages.error(request, 'The password reset link is invalid, possibly because it has already been used. Please request a new password reset.')
        return redirect('reset_password_request')
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = ResetPasswordConfirmForm(user, request.POST)
            if form.is_valid():
                form.save()

                user.set_password(form.cleaned_data['new_password1'])
                user.save()

                messages.success(request, 'Your new password has been saved.')
                logger.info(f"Password changed for user {user.pk} to {user.password}")
                return redirect('reset_password_complete')  # Redirect to login or another success page
            else:
                # If the form is not valid, render the page with the form errors
                return render(request, 'reset_password_confirm.html', {'uidb64': uidb64, 'token': token, 'form': form})
        else:
            # If the method is not POST, render the page with the form
            form = ResetPasswordConfirmForm(user)
            return render(request, 'reset_password_confirm.html', {'uidb64': uidb64, 'token': token, 'form': form})
    else:
        # If the user is None or the token check fails, redirect to the reset request
        return redirect('reset_password_request')

def reset_password_complete(request):
    return render(request, 'reset_password_complete.html')

def faq(request):
    return render(request, 'faq.html')

def pricing(request):
    return render(request, 'pricing.html')

def starter_package(request):
    return render(request, 'starter_package.html')

def professional_package(request):
    return render(request, 'professional_package.html')

def enterprise_package(request):
    return render(request, 'enterprise_package.html')

def custom_package(request):
    return render(request, 'custom_package.html')

def checkout(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.username = form.cleaned_data.get('username')
            user.save()
            #messages.success(request, 'You have successfully signed up!')
            return redirect('checkout')
        else:
            print("Form errors:", form.errors)
            if form.has_error('email', code='unique'):
                #messages.error(request, 'The email you entered is already attached to an account.')
                return render(request, 'checkout.html', {'form': form})
            else:
                #request.session['cart_items'] = [] #Clear the Cart After Checkout
                #messages.error(request, 'There was an error registering your account.')
                return render(request, 'checkout.html', {'form': form})
    else:
        form = CustomUserCreationForm()
    return render(request, 'checkout.html')

@login_required
def dashboard_home(request):
    context = {'username': request.user.username}
    return render(request, 'dashboard_home.html', context)

@login_required
def dashboard_base(request):
    context = {'CompanyName': request.user.CompanyName, 'email': request.user.email, 
                   'PhoneNumber': request.user.PhoneNumber, 'username': request.user.username, 
                   'first_name': request.user.first_name, 'last_name': request.user.last_name}
    return render(request, 'dashboard_base.html', context)

@login_required
def dashboard_account(request):
    if request.method == 'POST':
        form = CustomUserChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()

            messages.success(request, 'Your account details have successfully been updated!')
            return redirect('dashboard_account')
        else:
            messages.error(request, 'Input a valid website url or address.')
            logger.error(f"Form validation failed: {form.errors}")
            return render(request, 'dashboard_account.html', {'form': form})
    else:
        form = CustomUserChangeForm(instance=request.user)
        context = {'form': form, 'CompanyName': request.user.CompanyName, 'email': request.user.email, 
               'PhoneNumber': request.user.PhoneNumber, 'username': request.user.username, 
               'first_name': request.user.first_name, 'last_name': request.user.last_name}
    return render(request, 'dashboard_account.html', context)

@login_required
def dashboard_pricing(request):
    context = {'username': request.user.username}
    return render(request, 'dashboard_pricing.html', context)

@login_required
def dashboard_starter_package(request):
    return render(request, 'dashboard_starter_package.html')

@login_required
def dashboard_professional_package(request):
    return render(request, 'dashboard_professional_package.html')

@login_required
def dashboard_enterprise_package(request):
    return render(request, 'dashboard_enterprise_package.html')



@login_required
def dashboard_checkout(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.username = form.cleaned_data.get('username')
            user.save()
            #messages.success(request, 'You have successfully signed up!')
            return redirect('checkout')
        else:
            print("Form errors:", form.errors)
            if form.has_error('email', code='unique'):
                #messages.error(request, 'The email you entered is already attached to an account.')
                return render(request, 'checkout.html', {'form': form})
            else:
                #request.session['cart_items'] = [] #Clear the Cart After Checkout
                #messages.error(request, 'There was an error registering your account.')
                return render(request, 'checkout.html', {'form': form})
    else:
        form = CustomUserCreationForm()
        context = {'username': request.user.username}
    return render(request, 'dashboard_checkout.html', context)
    

@csrf_exempt
@require_POST
def add_to_cart(request):
    data = json.loads(request.body)
    item = {
        'item_name': data['item_name'],
        'price': float(data['price']),
        'subscription_price': float(data['subscription_price']),
        'quantity': int(data['quantity'])
    }

    if 'cart_items' not in request.session:     # Check if the cart is empty
        request.session['cart_items'] = []      # Initialize an empty cart

    # Check if the item with the same name already exists in the cart
    existing_item_index = None #no item with the same name was found in the cart
    for i, existing_item in enumerate(request.session['cart_items']):
        if existing_item['item_name'] == item['item_name']:
            existing_item_index = i
            break

    if existing_item_index is not None: #existing_item_index is not None = item with the same name was found in the cart
        # Update the quantity of the existing item
        request.session['cart_items'][existing_item_index]['quantity'] += item['quantity']
    else:
        # Add the new item to the cart
        request.session['cart_items'].append(item)

    request.session.modified = True

    # Recalculate cart details
    cart_count = sum(item['quantity'] for item in request.session['cart_items'])
    subtotal = sum(item['price'] * item['quantity'] for item in request.session['cart_items'])
    discount = calculate_discount(request.session['cart_items'])
    total = subtotal - discount

    print("222subtotal:", subtotal)  # Add this print statement to inspect the value of subtotal
    print("333discount:", discount)  # Add this print statement to inspect the value of discount
    print("4total:", total)        # Add this print statement to inspect the value of total
    print("5cart count:", cart_count)

    return JsonResponse({
        'status': 'success',
        'cartCount': cart_count,
        'subtotal': subtotal,
        'discount': discount,
        'total': total
    })


@csrf_exempt
@require_POST
def remove_from_cart(request):
    data = json.loads(request.body)
    item_name = data['item_name'] #GETS THE ITEM NAME FROM THE HTML
    # Initialize item quantity
    item_quantity = 0

    if 'cart_items' in request.session: # Check if there are items in the cart
        for item in request.session['cart_items']: # Iterate through each item in the cart
            if item['item_name'] == item_name:
                print("PREVIOUS ITEM QUANTITY:", item['quantity'])
                
                # Decrease the quantity of the existing item by 1
                item['quantity'] -= 1
                item_quantity = item['quantity']  # Update item quantity
                print("NEW ITEM QUANTITY:", item_quantity)
                request.session.modified = True
                # If quantity is 0 or less, remove the item from the cart
                if item['quantity'] <= 0:
                    request.session['cart_items'].remove(item)
                    request.session.modified = True
                break

        request.session.modified = True
                
    # Recalculate cart details
    cart_count = sum(item['quantity'] for item in request.session.get('cart_items', []))
    subtotal = sum(item['price'] * item['quantity'] for item in request.session.get('cart_items', []))
    discount = calculate_discount(request.session.get('cart_items', []))  # You need to implement calculate_discount function
    total = subtotal - discount

    print("subtotal:", subtotal)  # Add this print statement to inspect the value of subtotal
    print("discount:", discount)  # Add this print statement to inspect the value of discount
    print("total:", total)        # Add this print statement to inspect the value of total
    print("cart count:", cart_count)
    print("item name:", item_name)

    return JsonResponse({
        'status': 'success',
        'cartCount': cart_count,
        'subtotal': subtotal,
        'discount': discount,
        'total': total,
        'itemQuantity': item_quantity,
        'cartItems': item
    })


def calculate_discount(cart_items):
    discount = 0
    return discount

def get_cart_count(request):
    # Logic to retrieve the cart count from the session or database
    cart_count = sum(item['quantity'] for item in request.session.get('cart_items', []))
    # Return the cart count in a JSON response
    return JsonResponse({'cartCount': cart_count})   

def get_cart_details(request):
    # Retrieve cart details from session or database
    cart_items = request.session.get('cart_items', [])
    cart_count = sum(item['quantity'] for item in cart_items)
    subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
    discount = calculate_discount(cart_items)  # Implement calculate_discount function
    total = subtotal - discount

    print("0subtotal:", subtotal)  # Add this print statement to inspect the value of subtotal
    print("1discount:", discount)  # Add this print statement to inspect the value of discount
    print("2total:", total)        # Add this print statement to inspect the value of total
    print("3cart count:", cart_count)
    print("4cart items:", cart_items)

    # Return cart details in JSON response
    return JsonResponse({
        'cartCount': cart_count,
        'subtotal': subtotal,
        'discount': discount,
        'total': total,
        'cartItems': cart_items
    })

@login_required
def dashboard_subscriptions(request):
    context = {'username': request.user.username}
    return render(request, 'dashboard_subscriptions.html', context)

@login_required
def dashboard_billing(request):
    context = {'username': request.user.username}
    return render(request, 'dashboard_billing.html', context)

@login_required
def dashboard_analytics(request):
    context = {'username': request.user.username}
    return render(request, 'dashboard_analytics.html', context)

@login_required
def dashboard_support(request):
    if request.method == 'POST':
        form = ContactMessageForm(request.POST or None)
        if form.is_valid():
            # Validate email
            try:
                validate_email(form.cleaned_data['Email'])
            except ValidationError:
                form.add_error('Email', 'Invalid email address')
                messages.error(request, 'Invalid email address')
                return render(request, 'contact.html', {'form': form})

            # Validate phone number
            phone_number = form.cleaned_data['PhoneNumber']
            phone_number = ''.join(filter(str.isdigit, phone_number))  # Remove non-numeric characters
            if len(phone_number) != 10:  # Check if phone number has 10 digits
                form.add_error('PhoneNumber', 'Invalid phone number')
                messages.error(request, 'Invalid phone number')
                return render(request, 'contact.html', {'form': form})

            # Validate message length
            message = form.cleaned_data['Message']
            if len(message) > 200:  # Check if message length exceeds 250 characters
                form.add_error('Message', 'Message must be a maximum of 250 characters')
                messages.error(request, 'Max 250 characters')
                return render(request, 'contact.html', {'form': form})
            contact_message = form.save()
            Email = contact_message.Email
            protocol = 'https' if request.is_secure() else 'http'
            checkout_link = f"{protocol}://{request.get_host()}/checkout/"
            dynamic_template_data = {'checkout_link': checkout_link} #{{checkout_link}}
            # Send email using SendGrid
            send_email_via_sendgrid(
                request,
                to_email=Email,
                template_id='d-aca65f653797425fa3b857983365edd1',
                dynamic_template_data=dynamic_template_data
            )
            messages.success(request, 'Your message was successfully submitted!')
            return redirect('contact')
        else:
            messages.error(request, 'There was an error with your submission.')
            return render(request, 'contact.html', {'form': form})
    else:
        form = ContactMessageForm()
        context = {'CompanyName': request.user.CompanyName, 'email': request.user.email, 
                   'PhoneNumber': request.user.PhoneNumber, 'username': request.user.username, 
                   'first_name': request.user.first_name, 'last_name': request.user.last_name}
    return render(request, 'dashboard_support.html', context)

@login_required
def dashboard_contact(request):
    if request.method == 'POST':
        form = ContactMessageForm(request.POST or None)
        if form.is_valid():
            # Validate email
            try:
                validate_email(form.cleaned_data['Email'])
            except ValidationError:
                form.add_error('Email', 'Invalid email address')
                messages.error(request, 'Invalid email address')
                return render(request, 'contact.html', {'form': form})

            # Validate phone number
            phone_number = form.cleaned_data['PhoneNumber']
            phone_number = ''.join(filter(str.isdigit, phone_number))  # Remove non-numeric characters
            if len(phone_number) != 10:  # Check if phone number has 10 digits
                form.add_error('PhoneNumber', 'Invalid phone number')
                messages.error(request, 'Invalid phone number')
                return render(request, 'contact.html', {'form': form})

            # Validate message length
            message = form.cleaned_data['Message']
            if len(message) > 200:  # Check if message length exceeds 250 characters
                form.add_error('Message', 'Message must be a maximum of 250 characters')
                messages.error(request, 'Max 250 characters')
                return render(request, 'contact.html', {'form': form})
            contact_message = form.save()
            Email = contact_message.Email
            protocol = 'https' if request.is_secure() else 'http'
            checkout_link = f"{protocol}://{request.get_host()}/checkout/"
            dynamic_template_data = {'checkout_link': checkout_link} #{{checkout_link}}
            # Send email using SendGrid
            send_email_via_sendgrid(
                request,
                to_email=Email,
                template_id='d-aca65f653797425fa3b857983365edd1',
                dynamic_template_data=dynamic_template_data
            )
            messages.success(request, 'Your message was successfully submitted!')
            return redirect('contact')
        else:
            messages.error(request, 'There was an error with your submission.')
            return render(request, 'contact.html', {'form': form})
    else:
        form = ContactMessageForm()
        context = {'CompanyName': request.user.CompanyName, 'email': request.user.email, 'PhoneNumber': request.user.PhoneNumber, 'username': request.user.username, 'first_name': request.user.first_name, 'last_name': request.user.last_name}
    return render(request, 'dashboard_contact.html', context)

@login_required
def dashboard_faq(request):
    context = {'username': request.user.username}
    return render(request, 'dashboard_faq.html', context)

def error_500(request):
    context = {'username': request.user.username}
    return render(request, 'error_500.html', context)

def error_404(request):
    context = {'username': request.user.username}
    return render(request, 'error_404.html', context)

def error_401(request):
    context = {'username': request.user.username}
    return render(request, 'error_401.html', context)

#Staging Pages
'''
def portfolio_item(request):
    return render(request, 'portfolio_item.html')

def portfolio_overview(request):
    return render(request, 'portfolio_overview.html')

def blog_home(request):
    return render(request, 'portfolio_item.html')

def blog_post(request):
    return render(request, 'portfolio_overview.html')
'''

def checkout_success(request):
    return render(request, 'checkout_success.html')

def checkout_cancel(request):
    return render(request, 'checkout_cancel.html')

#SEND EMAIL AFTER STRIPE PAYMENT
STRIPE_API_KEY = settings.STRIPE_API_KEY
@csrf_exempt
def stripe_webhook(request):
    # Set up Stripe API key
    stripe.api_key = settings.STRIPE_API_KEY
    
    # Retrieve the event data from Stripe
    payload = request.body
    sig_header = request.headers['Stripe-Signature']
    #This webhook endpoint is used to handle payment events from Stripe on etchedn.com.
    endpoint_secret = "we_1OpjiwFsRyvdZ4PYAYiroO6e"

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        logger.error("ValueError: Invalid payload")
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        logger.error("SignatureVerificationError: Invalid signature")
        return HttpResponse(status=400)

    # Handle the event
    if event['type'] == 'payment_intent.succeeded':
        # Extract relevant information from the event data
        customer_email = event['data']['object']['charges']['data'][0]['billing_details']['email']
        amount = event['data']['object']['amount']
        # Log the extracted information
        logger.info(f"Payment succeeded for customer {customer_email} with amount {amount}")

        # Send email using SendGrid function
        dynamic_template_data = {}  # Add any additional data needed for the email template
        send_email_via_sendgrid(
                request,
                to_email=customer_email,
                template_id='d-3c357522f25d4f9fa2891b4a53587fc1',
                dynamic_template_data=dynamic_template_data
            )
    return HttpResponse(status=200)
