from __future__ import unicode_literals

import datetime

from django.core import signing
from django.db import models
from django.db import transaction
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible
from django.utils.crypto import get_random_string

from .. import app_settings as allauth_app_settings
from . import app_settings
from . import signals

from .utils import user_email
from .managers import EmailAddressManager, EmailConfirmationManager
from .adapter import get_adapter

from django.contrib.auth.models import User


@python_2_unicode_compatible
class EmailAddress(models.Model):

    user = models.ForeignKey(allauth_app_settings.USER_MODEL,
                             verbose_name=_('user'),
                             on_delete=models.CASCADE)
    email = models.EmailField(unique=app_settings.UNIQUE_EMAIL,
                              max_length=app_settings.EMAIL_MAX_LENGTH,
                              verbose_name=_('e-mail address'))
    verified = models.BooleanField(verbose_name=_('verified'), default=False)
    primary = models.BooleanField(verbose_name=_('primary'), default=False)

    objects = EmailAddressManager()

    class Meta:
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")
        if not app_settings.UNIQUE_EMAIL:
            unique_together = [("user", "email")]

    def __str__(self):
        return "%s (%s)" % (self.email, self.user)

    def set_as_primary(self, conditional=False):
        old_primary = EmailAddress.objects.get_primary(self.user)
        if old_primary:
            if conditional:
                return False
            old_primary.primary = False
            old_primary.save()
        self.primary = True
        self.save()
        user_email(self.user, self.email)
        self.user.save()
        return True

    def send_confirmation(self, request=None, signup=False):
        if app_settings.EMAIL_CONFIRMATION_HMAC:
            confirmation = EmailConfirmationHMAC(self)
        else:
            confirmation = EmailConfirmation.create(self)
        confirmation.send(request, signup=signup)
        return confirmation

    def change(self, request, new_email, confirm=True):
        """
        Given a new email address, change self and re-confirm.
        """
        try:
            atomic_transaction = transaction.atomic
        except AttributeError:
            atomic_transaction = transaction.commit_on_success

        with atomic_transaction():
            user_email(self.user, new_email)
            self.user.save()
            self.email = new_email
            self.verified = False
            self.save()
            if confirm:
                self.send_confirmation(request)


@python_2_unicode_compatible
class EmailConfirmation(models.Model):

    email_address = models.ForeignKey(EmailAddress,
                                      verbose_name=_('e-mail address'),
                                      on_delete=models.CASCADE)
    created = models.DateTimeField(verbose_name=_('created'),
                                   default=timezone.now)
    sent = models.DateTimeField(verbose_name=_('sent'), null=True)
    key = models.CharField(verbose_name=_('key'), max_length=64, unique=True)

    objects = EmailConfirmationManager()

    class Meta:
        verbose_name = _("email confirmation")
        verbose_name_plural = _("email confirmations")

    def __str__(self):
        return "confirmation for %s" % self.email_address

    @classmethod
    def create(cls, email_address):
        key = get_random_string(64).lower()
        return cls._default_manager.create(email_address=email_address,
                                           key=key)

    def key_expired(self):
        expiration_date = self.sent \
            + datetime.timedelta(days=app_settings
                                 .EMAIL_CONFIRMATION_EXPIRE_DAYS)
        return expiration_date <= timezone.now()
    key_expired.boolean = True

    def confirm(self, request):
        if not self.key_expired() and not self.email_address.verified:
            email_address = self.email_address
            get_adapter(request).confirm_email(request, email_address)
            signals.email_confirmed.send(sender=self.__class__,
                                         request=request,
                                         email_address=email_address)
            return email_address

    def send(self, request=None, signup=False):
        get_adapter(request).send_confirmation_mail(request, self, signup)
        self.sent = timezone.now()
        self.save()
        signals.email_confirmation_sent.send(sender=self.__class__,
                                             request=request,
                                             confirmation=self,
                                             signup=signup)


class EmailConfirmationHMAC:

    def __init__(self, email_address):
        self.email_address = email_address

    @property
    def key(self):
        return signing.dumps(
            obj=self.email_address.pk,
            salt=app_settings.SALT)

    @classmethod
    def from_key(cls, key):
        try:
            max_age = (
                60 * 60 * 24 * app_settings.EMAIL_CONFIRMATION_EXPIRE_DAYS)
            pk = signing.loads(
                key,
                max_age=max_age,
                salt=app_settings.SALT)
            ret = EmailConfirmationHMAC(EmailAddress.objects.get(pk=pk))
        except (signing.SignatureExpired,
                signing.BadSignature,
                EmailAddress.DoesNotExist):
            ret = None
        return ret

    def confirm(self, request):
        if not self.email_address.verified:
            email_address = self.email_address
            get_adapter(request).confirm_email(request, email_address)
            signals.email_confirmed.send(sender=self.__class__,
                                         request=request,
                                         email_address=email_address)
            return email_address

    def send(self, request=None, signup=False):
        get_adapter(request).send_confirmation_mail(request, self, signup)
        signals.email_confirmation_sent.send(sender=self.__class__,
                                             request=request,
                                             confirmation=self,
                                             signup=signup)

from django.contrib.auth.models import Permission, User
from django.db import models

class Hive(models.Model): #Hive Model,
    user = models.ManyToManyField(User, related_name = "member")
    #ManyToManyField to allow multiple users to assosciated to the Hive. I added a secondary index in order to make search faster and easier(Shaved a some code!!)
    course = models.CharField(max_length=500) #Name of the Hive

    def __str__(self):
        return self.course #Returns Hive in the admin Console making it easier for us to test and update results

class Notes(models.Model): #Notes Model for HIVES
    hive = models.ForeignKey(Hive, on_delete=models.CASCADE) #The Hive that the Notes are assosciated to
    hivepk = models.IntegerField(default = 0) #Adds the PK of the Hive in order to make sure notes are private and cannot be accessed through hives of the same Name
    notes_title = models.CharField(max_length=250) #Notes Name
    notes_file = models.FileField(default='') #File of the Notes Model(One for every notes, Hives can have many notes associated to them).

    def __str__(self):
        return self.notes_title

class ProfileNotes(models.Model): #Notes for the profiles
    user = models.ForeignKey(User, default = 1) #associated to a user, no need for PK because usernames are unique, and so are user models
    notes_title = models.CharField(max_length=250, blank = True) #title of the Notes
    notes_file = models.FileField(default='') #File of the Note

    def __str__(self):
        return self.notes_title

class MessageBoard(models.Model): #Each is a message to be added to each Hive's message board
    user = models.ForeignKey(User, default = 1) #User who posted
    hivepk = models.IntegerField(default = 0) #Pk of the assosicated Hive
    message = models.CharField(max_length = 500, blank = True) #Message posted
    time = models.DateTimeField(default=datetime.datetime.now, blank=True) #Date and Time message posted

    def __str__(self):
        return self.user

class Bio(models.Model): #The Bio model for user's bios
    user = models.ForeignKey(User, default = 1) #One for each user, unique to each of them.
    about = models.CharField(max_length = 500, blank = True) #What's in the bio
    #Bios are deleted when updated. A new one is created with the new bio
    def __str__(self):
        return self.user

class profilepic(models.Model):#Unused but basically it would use an ImageField to stoe a profile pic that would be asssociated to a user and then displayed
    user = models.ForeignKey(User, default = 1)
    image = models.ImageField(default = '')

    def __str__(self):
        return self.user

class University(models.Model): #Unused but would have told everybody what school you are from and allowed a filter in searching
    school = models.CharField(max_length = 900)
    students = models.ManyToManyField(User, related_name = "studentof")

    def __str__(self):
        return self.school
