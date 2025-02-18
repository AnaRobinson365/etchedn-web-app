from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager


# Create your models here.
class CustomUserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

class User(AbstractUser):
    CompanyName = models.CharField(max_length=255, blank=True, null=True)
    PhoneNumber = models.CharField(max_length=15)
    State = models.CharField(max_length=50)
    SignupDate = models.DateTimeField(auto_now_add=True)
    email = models.EmailField('email', unique=True)
    Website = models.URLField(max_length=255, blank=True, null=True)
    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    def __str__(self):
        return self.email

class NewsletterSubscription(models.Model):
    SubscriptionID = models.AutoField(primary_key=True)
    Email = models.EmailField(unique=True)
    def __str__(self):
        return self.Email  # Display the email as a string representation

SUBJECT_CHOICES = [
    ('initial-consultation', 'Initial Consultation'),
    ('technical-support', 'Technical Support'),
    ('questions', 'Questions'),
    ('other', 'Other'),
]
class ContactMessage(models.Model):
    MessageID = models.AutoField(primary_key=True)
    FullName = models.CharField(max_length=100)
    Email = models.EmailField()
    Subject = models.CharField(max_length=100, choices=SUBJECT_CHOICES)
    Message = models.TextField()
    PhoneNumber = models.CharField(max_length=15)
    ReceivedDate = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.Subject  + ' ' + self.FullName # Display the subject as a string representation

class PasswordReset(models.Model):
    ResetID = models.AutoField(primary_key=True)
    UserID = models.ForeignKey(User, on_delete=models.CASCADE)
    ResetToken = models.CharField(max_length=255)
    ExpiryDate = models.DateTimeField()
    def __str__(self):
        return f"Reset ID: {self.ResetID}, User: {self.UserID}, Expiry Date: {self.ExpiryDate}"