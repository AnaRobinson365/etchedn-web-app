from django.urls import path, re_path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.index, name='index'),  # Root URL
    path('about/', views.about, name='about'),  # About page
    path('contact/', views.contact, name='contact'),  # Contact page
    path('faq/', views.faq, name='faq'),  # FAQ page
    path('pricing/', views.pricing, name='pricing'),  # Pricing page
    path('starter_package/', views.starter_package, name='starter_package'),  # Starter Package Page
    path('professional_package/', views.professional_package, name='professional_package'),  # professional Package Page
    path('enterprise_package/', views.enterprise_package, name='enterprise_package'),  # enterprise Package Page
    path('dashboard_starter_package/', views.dashboard_starter_package, name='dashboard_starter_package'),  # Starter Package Page
    path('dashboard_professional_package/', views.dashboard_professional_package, name='dashboard_professional_package'),  # professional Package Page
    path('dashboard_enterprise_package/', views.dashboard_enterprise_package, name='dashboard_enterprise_package'),  # enterprise Package Page
    path('custom_package/', views.custom_package, name='custom_package'),  # custom flex Package Page
    path('login/', views.login_user, name='login'),  # login page
    path('signup/', views.signup, name='signup'),  # signup page
    path('reset_password_request/', views.reset_password_request, name='reset_password_request'),
    path('reset_password_confirm/<uidb64>/<token>/', views.reset_password_confirm, name='reset_password_confirm'),
    path('reset_password_complete/', views.reset_password_complete, name='reset_password_complete'),  # rest password Page
    path('checkout/', views.checkout, name='checkout'),  # checkout page
    path('dashboard_base/', views.dashboard_base, name='dashboard_base'),  # dashboard home Page
    path('dashboard_home/', views.dashboard_home, name='dashboard_home'),  # dashboard home Page
    path('dashboard_account/', views.dashboard_account, name='dashboard_account'),
    path('dashboard_billing/', views.dashboard_billing, name='dashboard_billing'),
    path('dashboard_analytics/', views.dashboard_analytics, name='dashboard_analytics'),
    path('dashboard_subscriptions/', views.dashboard_subscriptions, name='dashboard_subscriptions'),
    path('dashboard_support/', views.dashboard_support, name='dashboard_support'),
    path('dashboard_contact/', views.dashboard_contact, name='dashboard_contact'),
    path('dashboard_pricing/', views.dashboard_pricing, name='dashboard_pricing'),
    path('dashboard_checkout/', views.dashboard_checkout, name='dashboard_checkout'),
    path('add_to_cart/', views.add_to_cart, name='add_to_cart'),
    path('remove_from_cart/', views.remove_from_cart, name='remove_from_cart'),
    path('get_cart_count/', views.get_cart_count, name='get_cart_count'),
    path('get_cart_details/', views.get_cart_details, name='get_cart_details'),
    path('checkout_success/', views.checkout_success, name='checkout_success'),
    path('checkout_cancel/', views.checkout_cancel, name='checkout_cancel'),
    path('dashboard_faq/', views.dashboard_faq, name='dashboard_faq'),
    path('error_500/', views.error_500, name='error_500'),  # error_500
    path('error_404/', views.error_404, name='error_404'),  # error_404
    path('error_401/', views.error_401, name='error_401'),  # error_401
    path('stripe_webhook/', views.stripe_webhook, name='stripe_webhook')
]

#Staging Pages
"""
path('portfolio_item/', views.portfolio_item, name='portfolio_item'),  # Portfolio item page
path('portfolio_overview/', views.portfolio_overview, name='portfolio_overview'),  # Portfolio overview page
path('blog_post/', views.blog_post, name='blog_post'),  # Blog Post page
path('blog_home/', views.blog_home, name='blog_home')  # Blog Home page
"""

