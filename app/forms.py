from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm, SetPasswordForm, AuthenticationForm, UserChangeForm
from django.contrib.auth import get_user_model
from .models import (
    User, NewsletterSubscription, ContactMessage, PasswordReset)

User = get_user_model()
class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'PhoneNumber', 'State', 'CompanyName', 'password1', 'password2')
    def clean(self):
        cleaned_data = super().clean()
        first_name = cleaned_data.get('first_name')
        last_name = cleaned_data.get('last_name')
        if first_name == last_name:
            raise forms.ValidationError("First name cannot be equal to last name.")
        
class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ['Website']

class ResetPasswordForm(PasswordResetForm):
    def clean_email(self):
        email = self.cleaned_data.get('email', '')
        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError("There is no account registered with the specified email address!")
        return email
    
class ResetPasswordConfirmForm(SetPasswordForm):
    class Meta:
        model = User
        fields = ['new_password1', 'new_password2']

class NewsletterSubscriptionForm(forms.ModelForm):
    class Meta:
        model = NewsletterSubscription
        fields = ['Email']

class ContactMessageForm(forms.ModelForm):
    class Meta:
        model = ContactMessage
        fields = ['FullName', 'Email', 'Subject', 'Message', 'PhoneNumber']
    def clean(self):
        cleaned_data = super().clean()
        first_name = cleaned_data.get('FullName').split()[0]
        last_name = cleaned_data.get('FullName').split()[-1]
        if first_name == last_name:
            raise forms.ValidationError("First name cannot be equal to last name.")