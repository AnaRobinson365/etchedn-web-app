from django.contrib import admin
from .models import User, NewsletterSubscription, ContactMessage, PasswordReset  
from django.contrib.auth.admin import UserAdmin

#Register models
admin.site.register(NewsletterSubscription)
admin.site.register(ContactMessage)

admin.site.register(PasswordReset)


#custom display
class UserAdmin(admin.ModelAdmin):
    list_display = ('first_name', 'last_name', 'email') 
    search_fields = ['email', 'first_name', 'last_name'] 

# Then register the model with the custom admin class
admin.site.register(User, UserAdmin)
