from django.http import (HttpResponseRedirect, Http404,
                         HttpResponsePermanentRedirect)
from django.views.generic.base import TemplateResponseMixin, View, TemplateView
from django.views.generic.edit import FormView
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from django.shortcuts import redirect, render
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.decorators import method_decorator

from ..compat import is_anonymous, is_authenticated, reverse, reverse_lazy
from ..exceptions import ImmediateHttpResponse
from ..utils import get_form_class, get_request_param, get_current_site

from .utils import (get_next_redirect_url, complete_signup,
                    get_login_redirect_url, perform_login,
                    passthrough_next_redirect_url, url_str_to_user_pk,
                    logout_on_password_change)
from .forms import (
    AddEmailForm, ChangePasswordForm,
    LoginForm, ResetPasswordKeyForm,
    ResetPasswordForm, SetPasswordForm, SignupForm, UserTokenForm)
from .utils import sync_user_email_addresses
from .models import EmailAddress, EmailConfirmation, EmailConfirmationHMAC

from . import signals
from . import app_settings

from .adapter import get_adapter

from django.core.files.storage import FileSystemStorage
from django.db.models import Q
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.db.models import Q
from .forms import HiveForm, NotesForm, AddForm, RemoveForm, DeleteForm, BioForm, ProfileNotesForm, SearchUserForm, SearchUniversityForm, MessageForm
from .models import Notes, Hive, profilepic, Bio, ProfileNotes, MessageBoard
from django.contrib.auth.models import User


sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters('password', 'password1', 'password2'))


def _ajax_response(request, response, form=None):
    if request.is_ajax():
        if (isinstance(response, HttpResponseRedirect) or isinstance(
                response, HttpResponsePermanentRedirect)):
            redirect_to = response['Location']
        else:
            redirect_to = None
        response = get_adapter(request).ajax_response(
            request,
            response,
            form=form,
            redirect_to=redirect_to)
    return response


class RedirectAuthenticatedUserMixin(object):
    def dispatch(self, request, *args, **kwargs):
        # WORKAROUND: https://code.djangoproject.com/ticket/19316
        self.request = request
        # (end WORKAROUND)
        if is_authenticated(request.user) and \
                app_settings.AUTHENTICATED_LOGIN_REDIRECTS:
            redirect_to = self.get_authenticated_redirect_url()
            response = HttpResponseRedirect(redirect_to)
            return _ajax_response(request, response)
        else:
            response = super(RedirectAuthenticatedUserMixin,
                             self).dispatch(request,
                                            *args,
                                            **kwargs)
        return response

    def get_authenticated_redirect_url(self):
        redirect_field_name = self.redirect_field_name
        return get_login_redirect_url(self.request,
                                      url=self.get_success_url(),
                                      redirect_field_name=redirect_field_name)


class AjaxCapableProcessFormViewMixin(object):

    def post(self, request, *args, **kwargs):
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            response = self.form_valid(form)
        else:
            response = self.form_invalid(form)
        return _ajax_response(self.request, response, form=form)


class LoginView(RedirectAuthenticatedUserMixin,
                AjaxCapableProcessFormViewMixin,
                FormView):
    form_class = LoginForm
    template_name = "account/login." + app_settings.TEMPLATE_EXTENSION
    success_url = ""
    redirect_field_name = "next"

    @sensitive_post_parameters_m
    def dispatch(self, request, *args, **kwargs):
        return super(LoginView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(LoginView, self).get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, 'login', self.form_class)

    def form_valid(self, form):
        success_url = self.get_success_url()
        try:
            return form.login(self.request, redirect_url=success_url)
        except ImmediateHttpResponse as e:
            return e.response

    def get_success_url(self):
        # Explicitly passed ?next= URL takes precedence
        ret = (get_next_redirect_url(
            self.request,
            self.redirect_field_name) or self.success_url)
        return ret

    def get_context_data(self, **kwargs):
        ret = super(LoginView, self).get_context_data(**kwargs)
        signup_url = passthrough_next_redirect_url(self.request,
                                                   reverse("account_signup"),
                                                   self.redirect_field_name)
        redirect_field_value = get_request_param(self.request,
                                                 self.redirect_field_name)
        site = get_current_site(self.request)

        ret.update({"signup_url": signup_url,
                    "site": site,
                    "redirect_field_name": self.redirect_field_name,
                    "redirect_field_value": redirect_field_value})
        return ret

login = LoginView.as_view()


class CloseableSignupMixin(object):
    template_name_signup_closed = (
        "account/signup_closed." + app_settings.TEMPLATE_EXTENSION)

    def dispatch(self, request, *args, **kwargs):
        # WORKAROUND: https://code.djangoproject.com/ticket/19316
        self.request = request
        # (end WORKAROUND)
        try:
            if not self.is_open():
                return self.closed()
        except ImmediateHttpResponse as e:
            return e.response
        return super(CloseableSignupMixin, self).dispatch(request,
                                                          *args,
                                                          **kwargs)

    def is_open(self):
        return get_adapter(self.request).is_open_for_signup(self.request)

    def closed(self):
        response_kwargs = {
            "request": self.request,
            "template": self.template_name_signup_closed,
        }
        return self.response_class(**response_kwargs)


class SignupView(RedirectAuthenticatedUserMixin, CloseableSignupMixin,
                 AjaxCapableProcessFormViewMixin, FormView):
    template_name = "account/signup." + app_settings.TEMPLATE_EXTENSION
    form_class = SignupForm
    redirect_field_name = "next"
    success_url = None

    @sensitive_post_parameters_m
    def dispatch(self, request, *args, **kwargs):
        return super(SignupView, self).dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, 'signup', self.form_class)

    def get_success_url(self):
        # Explicitly passed ?next= URL takes precedence
        ret = (
            get_next_redirect_url(
                self.request,
                self.redirect_field_name) or self.success_url)
        return ret

    def form_valid(self, form):
        # By assigning the User to a property on the view, we allow subclasses
        # of SignupView to access the newly created User instance
        self.user = form.save(self.request)
        try:
            return complete_signup(
                self.request, self.user,
                app_settings.EMAIL_VERIFICATION,
                self.get_success_url())
        except ImmediateHttpResponse as e:
            return e.response

    def get_context_data(self, **kwargs):
        ret = super(SignupView, self).get_context_data(**kwargs)
        form = ret['form']
        email = self.request.session.get('account_verified_email')
        email_keys = ['email']
        if app_settings.SIGNUP_EMAIL_ENTER_TWICE:
            email_keys.append('email2')
        for email_key in email_keys:
            form.fields[email_key].initial = email
        login_url = passthrough_next_redirect_url(self.request,
                                                  reverse("account_login"),
                                                  self.redirect_field_name)
        redirect_field_name = self.redirect_field_name
        redirect_field_value = get_request_param(self.request,
                                                 redirect_field_name)
        ret.update({"login_url": login_url,
                    "redirect_field_name": redirect_field_name,
                    "redirect_field_value": redirect_field_value})
        return ret

signup = SignupView.as_view()


class ConfirmEmailView(TemplateResponseMixin, View):

    template_name = "account/email_confirm." + app_settings.TEMPLATE_EXTENSION

    def get(self, *args, **kwargs):
        try:
            self.object = self.get_object()
            if app_settings.CONFIRM_EMAIL_ON_GET:
                return self.post(*args, **kwargs)
        except Http404:
            self.object = None
        ctx = self.get_context_data()
        return self.render_to_response(ctx)

    def post(self, *args, **kwargs):
        self.object = confirmation = self.get_object()
        confirmation.confirm(self.request)
        get_adapter(self.request).add_message(
            self.request,
            messages.SUCCESS,
            'account/messages/email_confirmed.txt',
            {'email': confirmation.email_address.email})
        if app_settings.LOGIN_ON_EMAIL_CONFIRMATION:
            resp = self.login_on_confirm(confirmation)
            if resp is not None:
                return resp
        # Don't -- allauth doesn't touch is_active so that sys admin can
        # use it to block users et al
        #
        # user = confirmation.email_address.user
        # user.is_active = True
        # user.save()
        redirect_url = self.get_redirect_url()
        if not redirect_url:
            ctx = self.get_context_data()
            return self.render_to_response(ctx)
        return redirect(redirect_url)

    def login_on_confirm(self, confirmation):
        """
        Simply logging in the user may become a security issue. If you
        do not take proper care (e.g. don't purge used email
        confirmations), a malicious person that got hold of the link
        will be able to login over and over again and the user is
        unable to do anything about it. Even restoring their own mailbox
        security will not help, as the links will still work. For
        password reset this is different, this mechanism works only as
        long as the attacker has access to the mailbox. If they no
        longer has access they cannot issue a password request and
        intercept it. Furthermore, all places where the links are
        listed (log files, but even Google Analytics) all of a sudden
        need to be secured. Purging the email confirmation once
        confirmed changes the behavior -- users will not be able to
        repeatedly confirm (in case they forgot that they already
        clicked the mail).

        All in all, opted for storing the user that is in the process
        of signing up in the session to avoid all of the above.  This
        may not 100% work in case the user closes the browser (and the
        session gets lost), but at least we're secure.
        """
        user_pk = None
        user_pk_str = get_adapter(self.request).unstash_user(self.request)
        if user_pk_str:
            user_pk = url_str_to_user_pk(user_pk_str)
        user = confirmation.email_address.user
        if user_pk == user.pk and is_anonymous(self.request.user):
            return perform_login(self.request,
                                 user,
                                 app_settings.EmailVerificationMethod.NONE,
                                 # passed as callable, as this method
                                 # depends on the authenticated state
                                 redirect_url=self.get_redirect_url)

        return None

    def get_object(self, queryset=None):
        key = self.kwargs['key']
        emailconfirmation = EmailConfirmationHMAC.from_key(key)
        if not emailconfirmation:
            if queryset is None:
                queryset = self.get_queryset()
            try:
                emailconfirmation = queryset.get(key=key.lower())
            except EmailConfirmation.DoesNotExist:
                raise Http404()
        return emailconfirmation

    def get_queryset(self):
        qs = EmailConfirmation.objects.all_valid()
        qs = qs.select_related("email_address__user")
        return qs

    def get_context_data(self, **kwargs):
        ctx = kwargs
        ctx["confirmation"] = self.object
        return ctx

    def get_redirect_url(self):
        return get_adapter(self.request).get_email_confirmation_redirect_url(
            self.request)

confirm_email = ConfirmEmailView.as_view()


class EmailView(AjaxCapableProcessFormViewMixin, FormView):
    template_name = "account/email." + app_settings.TEMPLATE_EXTENSION
    form_class = AddEmailForm
    success_url = reverse_lazy('account_email')

    def get_form_class(self):
        return get_form_class(app_settings.FORMS, 'add_email', self.form_class)

    def dispatch(self, request, *args, **kwargs):
        sync_user_email_addresses(request.user)
        return super(EmailView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(EmailView, self).get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        email_address = form.save(self.request)
        get_adapter(self.request).add_message(
            self.request,
            messages.INFO,
            'account/messages/'
            'email_confirmation_sent.txt',
            {'email': form.cleaned_data["email"]})
        signals.email_added.send(sender=self.request.user.__class__,
                                 request=self.request,
                                 user=self.request.user,
                                 email_address=email_address)
        return super(EmailView, self).form_valid(form)

    def post(self, request, *args, **kwargs):
        res = None
        if "action_add" in request.POST:
            res = super(EmailView, self).post(request, *args, **kwargs)
        elif request.POST.get("email"):
            if "action_send" in request.POST:
                res = self._action_send(request)
            elif "action_remove" in request.POST:
                res = self._action_remove(request)
            elif "action_primary" in request.POST:
                res = self._action_primary(request)
            res = res or HttpResponseRedirect(reverse('account_email'))
            # Given that we bypassed AjaxCapableProcessFormViewMixin,
            # we'll have to call invoke it manually...
            res = _ajax_response(request, res)
        else:
            # No email address selected
            res = HttpResponseRedirect(reverse('account_email'))
            res = _ajax_response(request, res)
        return res

    def _action_send(self, request, *args, **kwargs):
        email = request.POST["email"]
        try:
            email_address = EmailAddress.objects.get(
                user=request.user,
                email=email,
            )
            get_adapter(request).add_message(
                request,
                messages.INFO,
                'account/messages/'
                'email_confirmation_sent.txt',
                {'email': email})
            email_address.send_confirmation(request)
            return HttpResponseRedirect(self.get_success_url())
        except EmailAddress.DoesNotExist:
            pass

    def _action_remove(self, request, *args, **kwargs):
        email = request.POST["email"]
        try:
            email_address = EmailAddress.objects.get(
                user=request.user,
                email=email
            )
            if email_address.primary:
                get_adapter(request).add_message(
                    request,
                    messages.ERROR,
                    'account/messages/'
                    'cannot_delete_primary_email.txt',
                    {"email": email})
            else:
                email_address.delete()
                signals.email_removed.send(sender=request.user.__class__,
                                           request=request,
                                           user=request.user,
                                           email_address=email_address)
                get_adapter(request).add_message(
                    request,
                    messages.SUCCESS,
                    'account/messages/email_deleted.txt',
                    {"email": email})
                return HttpResponseRedirect(self.get_success_url())
        except EmailAddress.DoesNotExist:
            pass

    def _action_primary(self, request, *args, **kwargs):
        email = request.POST["email"]
        try:
            email_address = EmailAddress.objects.get_for_user(
                user=request.user,
                email=email
            )
            # Not primary=True -- Slightly different variation, don't
            # require verified unless moving from a verified
            # address. Ignore constraint if previous primary email
            # address is not verified.
            if not email_address.verified and \
                    EmailAddress.objects.filter(user=request.user,
                                                verified=True).exists():
                get_adapter(request).add_message(
                    request,
                    messages.ERROR,
                    'account/messages/'
                    'unverified_primary_email.txt')
            else:
                # Sending the old primary address to the signal
                # adds a db query.
                try:
                    from_email_address = EmailAddress.objects \
                        .get(user=request.user, primary=True)
                except EmailAddress.DoesNotExist:
                    from_email_address = None
                email_address.set_as_primary()
                get_adapter(request).add_message(
                    request,
                    messages.SUCCESS,
                    'account/messages/primary_email_set.txt')
                signals.email_changed \
                    .send(sender=request.user.__class__,
                          request=request,
                          user=request.user,
                          from_email_address=from_email_address,
                          to_email_address=email_address)
                return HttpResponseRedirect(self.get_success_url())
        except EmailAddress.DoesNotExist:
            pass

    def get_context_data(self, **kwargs):
        ret = super(EmailView, self).get_context_data(**kwargs)
        # NOTE: For backwards compatibility
        ret['add_email_form'] = ret.get('form')
        # (end NOTE)
        return ret

email = login_required(EmailView.as_view())


class PasswordChangeView(AjaxCapableProcessFormViewMixin, FormView):
    template_name = (
        "account/password_change." + app_settings.TEMPLATE_EXTENSION)
    form_class = ChangePasswordForm
    success_url = reverse_lazy("account_change_password")

    def get_form_class(self):
        return get_form_class(app_settings.FORMS,
                              'change_password',
                              self.form_class)

    @sensitive_post_parameters_m
    def dispatch(self, request, *args, **kwargs):
        if not request.user.has_usable_password():
            return HttpResponseRedirect(reverse('account_set_password'))
        return super(PasswordChangeView, self).dispatch(request, *args,
                                                        **kwargs)

    def get_form_kwargs(self):
        kwargs = super(PasswordChangeView, self).get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        logout_on_password_change(self.request, form.user)
        get_adapter(self.request).add_message(
            self.request,
            messages.SUCCESS,
            'account/messages/password_changed.txt')
        signals.password_changed.send(sender=self.request.user.__class__,
                                      request=self.request,
                                      user=self.request.user)
        return super(PasswordChangeView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        ret = super(PasswordChangeView, self).get_context_data(**kwargs)
        # NOTE: For backwards compatibility
        ret['password_change_form'] = ret.get('form')
        # (end NOTE)
        return ret

password_change = login_required(PasswordChangeView.as_view())


class PasswordSetView(AjaxCapableProcessFormViewMixin, FormView):
    template_name = "account/password_set." + app_settings.TEMPLATE_EXTENSION
    form_class = SetPasswordForm
    success_url = reverse_lazy("account_set_password")

    def get_form_class(self):
        return get_form_class(app_settings.FORMS,
                              'set_password',
                              self.form_class)

    @sensitive_post_parameters_m
    def dispatch(self, request, *args, **kwargs):
        if request.user.has_usable_password():
            return HttpResponseRedirect(reverse('account_change_password'))
        return super(PasswordSetView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(PasswordSetView, self).get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        logout_on_password_change(self.request, form.user)
        get_adapter(self.request).add_message(
            self.request,
            messages.SUCCESS,
            'account/messages/password_set.txt')
        signals.password_set.send(sender=self.request.user.__class__,
                                  request=self.request, user=self.request.user)
        return super(PasswordSetView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        ret = super(PasswordSetView, self).get_context_data(**kwargs)
        # NOTE: For backwards compatibility
        ret['password_set_form'] = ret.get('form')
        # (end NOTE)
        return ret

password_set = login_required(PasswordSetView.as_view())


class PasswordResetView(AjaxCapableProcessFormViewMixin, FormView):
    template_name = "account/password_reset." + app_settings.TEMPLATE_EXTENSION
    form_class = ResetPasswordForm
    success_url = reverse_lazy("account_reset_password_done")
    redirect_field_name = "next"

    def get_form_class(self):
        return get_form_class(app_settings.FORMS,
                              'reset_password',
                              self.form_class)

    def form_valid(self, form):
        form.save(self.request)
        return super(PasswordResetView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        ret = super(PasswordResetView, self).get_context_data(**kwargs)
        login_url = passthrough_next_redirect_url(self.request,
                                                  reverse("account_login"),
                                                  self.redirect_field_name)
        # NOTE: For backwards compatibility
        ret['password_reset_form'] = ret.get('form')
        # (end NOTE)
        ret.update({"login_url": login_url})
        return ret

password_reset = PasswordResetView.as_view()


class PasswordResetDoneView(TemplateView):
    template_name = (
        "account/password_reset_done." + app_settings.TEMPLATE_EXTENSION)

password_reset_done = PasswordResetDoneView.as_view()


class PasswordResetFromKeyView(AjaxCapableProcessFormViewMixin, FormView):
    template_name = (
        "account/password_reset_from_key." + app_settings.TEMPLATE_EXTENSION)
    form_class = ResetPasswordKeyForm
    success_url = reverse_lazy("account_reset_password_from_key_done")

    def get_form_class(self):
        return get_form_class(app_settings.FORMS,
                              'reset_password_from_key',
                              self.form_class)

    def dispatch(self, request, uidb36, key, **kwargs):
        self.request = request
        self.key = key
        # (Ab)using forms here to be able to handle errors in XHR #890
        token_form = UserTokenForm(data={'uidb36': uidb36, 'key': key})

        if not token_form.is_valid():
            self.reset_user = None
            response = self.render_to_response(
                self.get_context_data(token_fail=True)
            )
            return _ajax_response(self.request, response, form=token_form)
        else:
            self.reset_user = token_form.reset_user
            return super(PasswordResetFromKeyView, self).dispatch(request,
                                                                  uidb36,
                                                                  key,
                                                                  **kwargs)

    def get_form_kwargs(self):
        kwargs = super(PasswordResetFromKeyView, self).get_form_kwargs()
        kwargs["user"] = self.reset_user
        kwargs["temp_key"] = self.key
        return kwargs

    def form_valid(self, form):
        form.save()
        get_adapter(self.request).add_message(
            self.request,
            messages.SUCCESS,
            'account/messages/password_changed.txt')
        signals.password_reset.send(sender=self.reset_user.__class__,
                                    request=self.request,
                                    user=self.reset_user)

        if app_settings.LOGIN_ON_PASSWORD_RESET:
            return perform_login(
                self.request, self.reset_user,
                email_verification=app_settings.EMAIL_VERIFICATION)

        return super(PasswordResetFromKeyView, self).form_valid(form)

password_reset_from_key = PasswordResetFromKeyView.as_view()


class PasswordResetFromKeyDoneView(TemplateView):
    template_name = (
        "account/password_reset_from_key_done." +
        app_settings.TEMPLATE_EXTENSION)

password_reset_from_key_done = PasswordResetFromKeyDoneView.as_view()


class LogoutView(TemplateResponseMixin, View):

    template_name = "account/logout." + app_settings.TEMPLATE_EXTENSION
    redirect_field_name = "account_login"

    def get(self, *args, **kwargs):
        if app_settings.LOGOUT_ON_GET:
            return self.post(*args, **kwargs)
        if not is_authenticated(self.request.user):
            return redirect(self.get_redirect_url())
        ctx = self.get_context_data()
        return self.render_to_response(ctx)

    def post(self, *args, **kwargs):
        url = self.get_redirect_url()
        if is_authenticated(self.request.user):
            self.logout()
        return redirect(url)

    def logout(self):
        get_adapter(self.request).add_message(
            self.request,
            messages.SUCCESS,
            'account/messages/logged_out.txt')
        auth_logout(self.request)

    def get_context_data(self, **kwargs):
        ctx = kwargs
        redirect_field_value = get_request_param(self.request,
                                                 self.redirect_field_name)
        ctx.update({
            "redirect_field_name": self.redirect_field_name,
            "redirect_field_value": redirect_field_value})
        return ctx

    def get_redirect_url(self):
        return (
            get_next_redirect_url(
                self.request,
                self.redirect_field_name) or get_adapter(
                    self.request).get_logout_redirect_url(
                        self.request))

logout = LogoutView.as_view()


class AccountInactiveView(TemplateView):
    template_name = (
        'account/account_inactive.' + app_settings.TEMPLATE_EXTENSION)

account_inactive = AccountInactiveView.as_view()


class EmailVerificationSentView(TemplateView):
    template_name = (
        'account/verification_sent.' + app_settings.TEMPLATE_EXTENSION)

email_verification_sent = EmailVerificationSentView.as_view()



def settings(request):
    return render(request,'account/settings.html')


def profiles(request, username):
    u = User.objects.get(username = username)#get's username passed in url
    if not request.user.is_authenticated():
        return render(request, 'account/login.html')

    socks = User.objects.filter(username = username) #gets user with the username typed in URL
    top = socks.first() #filters the user from the query set
    biop = Bio.objects.filter(user=top) #finds the user's bio
    if not biop:
        profiledat = "Nothing Here!" #If no bio show this
    else:
        profiledat = biop.first().about #Show bio

    user_notes = ProfileNotes.objects.all() #gets all their notes, will display on page

    return render(request, 'account/otherprofiles.html', {'user': username, 'u': u, 'bio': profiledat, 'portfolio': user_notes })

def profile(request):
    if not request.user.is_authenticated():
        return render(request, 'account/login.html')
    else:
        form = BioForm(request.POST or None) #gets data from bioform
        NotesForm = ProfileNotesForm(request.POST or None, request.FILES or None) #gets form data for notes
        Remove = DeleteForm()
        if request.method == "POST":
            print request.POST
            if 'Remove' in request.POST: #if the user asked to remove another user or themselves this will run

                Remove = DeleteForm(request.POST or None)
                if Remove.is_valid():

                    notes = Remove.cleaned_data['notes_title']
                    print notes
                    x = ProfileNotes.objects.filter(user = request.user, notes_title = notes).delete()
                    user_notes = ProfileNotes.objects.all()

                    biop = Bio.objects.filter(user=request.user)
                    profiledat = biop.first()
                    user_notes = ProfileNotes.objects.all()

                    return render(request, 'account/account_profile.html', {'user': request.user, 'bio': profiledat.about, 'bioform' : form, 'uploader' : NotesForm, 'portfolio': user_notes, 'remove' : Remove})

        if NotesForm.is_valid(): #Valid meaning All required elements of the form are sent in, in this case a title and file

            notes = NotesForm.save(commit = False) #creates new ProfileNotes model with this data
            notes.user = request.user #commits current user to the model
            notes.notes_title.lower()
            # notes.notes_file = request.FILES['notes_file']
            notes.save() #saves model changes
            user_notes = ProfileNotes.objects.all()

            biop = Bio.objects.filter(user=request.user)
            profiledat = biop.first()
            user_notes = ProfileNotes.objects.all()

            return render(request, 'account/account_profile.html', {'user': request.user, 'bio': profiledat.about, 'bioform' : form, 'uploader' : NotesForm, 'portfolio': user_notes, 'remove' : Remove})

        if form.is_valid(): #Valid meaning All required elements of the form are sent in, in this case a title and file
            z = Bio.objects.filter(user=request.user).delete() #searches for the current bio of the user and deletes it, done so bios can be searchable by user, but also only one be associated to them

            bio = form.save(commit = False) #saves new bio
            bio.user = request.user #saves this bio to current user
            bio.save() #saves model to db

            biop = Bio.objects.filter(user=request.user)
            profiledat = biop.first()
            user_notes = ProfileNotes.objects.all()

            return render(request, 'account/account_profile.html', {'user': request.user, 'bio': profiledat.about, 'bioform' : form, 'uploader' : NotesForm, 'portfolio': user_notes, 'remove' : Remove})

        biop = Bio.objects.filter(user=request.user) #filters in bio model for this current user's
        if not biop:
            profiledat = "Add A Bio!" #default bio if the user currently has none
        else:
            profiledat = biop.first().about #gets user's bio from queryset

        user_notes = ProfileNotes.objects.all() #gets all profile notes in the DB, these are filtered through in the template until only the current user's notes are found and shown

        return render(request, 'account/account_profile.html', {'user': request.user, 'bio': profiledat, 'bioform' : form, 'uploader' : NotesForm, 'portfolio': user_notes, 'remove' : Remove})

def myHive(request):
    if not request.user.is_authenticated():
        return render(request, 'account/login.html')
    else:
        form = HiveForm(request.POST or None, request.FILES or None) #Gets data for Hive Form
        if form.is_valid(): #if the requirements of the HiveForm are met, it is valid
            hive = form.save(commit=False) #saves form data to new hive
            hive.save() #saves Hive to DB
            hive.user.add(request.user) #adds this user to the newly made Hive
            hives = request.user.member.all() #Members is a secondary index, finds all Hives a user is a member of
            notes_results = Notes.objects.all() #Gets all notes
            return render(request, 'account/my_hive.html', {
                'hives': hives,
                'notes': notes_results,
                'form': form,

            })


        hives = request.user.member.all() #Gets all hives the user is member of.
        notes_results = Notes.objects.all()
        context = {
            'form': form,
            'hives': hives,
            'notes': notes_results,

        }


        return render(request, 'account/my_hive.html', context)

from django.http import HttpResponse

import os.path

def detail(request, hive_id): #Inside the Hive

    #Forms work just as described in above sections, they get the data they are looking for from the post request
    form = NotesForm(request.POST or None, request.FILES or None)
    Dorm = AddForm()
    Remove = RemoveForm()
    Del = DeleteForm()
    Comm = MessageForm(request.POST or None)
    proper = 0 #This will check for errors and message the user accordingly
    hive = get_object_or_404(Hive, pk=hive_id) #gets the hive we are in

    if not Hive.objects.filter(pk = hive_id, user = request.user): #Prevents users from brute forcing into a hive by typing in the /[hive_number]
        return redirect('/accounts/profile')


    if form.is_valid():                             #Add Notes to the Hive
        hives_notes = hive.notes_set.all()
        notes = form.save(commit=False)
        notes.hive = hive
        notes.hivepk = int(hive_id) #converts hive_id into into and adds it to the notes
        notes.notes_title = notes.notes_title.lower()#forces the name of all notes to be put into lowercase in order to make deletetions easier

        notes.notes_file = request.FILES['notes_file']#saves the file
        notes.save() #saves notes model
        user = request.user
        hive = get_object_or_404(Hive,pk = hive_id)
        notes = Notes.objects.all()
        persons = hive.user.all()

        board = MessageBoard.objects.all()
        return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete' : Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})


        #So here is how the following few conditionals work, if there is a post request the view checks to see where it came from
    if request.method == "POST":
        if 'add' in request.POST: #checks if request is from the add button, else it moves on
            Dorm = AddForm(request.POST or None)
            if Dorm.is_valid():

                added_user = Dorm.cleaned_data['addUser'] #gets data from charfield form .

                exist = User.objects.filter(username = added_user)

                if not exist: # if the user does not exist the following code returns the page with an error message telling the user they screwed up
                    proper = 4
                    user = request.user
                    hive = get_object_or_404(Hive, pk=hive_id)
                    notes = Notes.objects.all()
                    persons = hive.user.all()
                    board = MessageBoard.objects.all()
                    if not persons:
                        Hive.objects.filter(pk = hive_id).delete()

                        return redirect('/accounts/myHive')
                    return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete' : Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})
                if not hive.user.filter(username = exist.first().username): #if the user exists but isn't in the hive add them
                    hive.user.add(exist.first())
                elif hive.user.filter(username = exist.first().username): #if the user does exist but is in the hive this will let them know they screwed up
                    proper = 1
                user = request.user
                hive = get_object_or_404(Hive, pk=hive_id)
                notes = Notes.objects.all()
                persons = hive.user.all()
                board = MessageBoard.objects.all()
                return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete' : Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})
        else:
            if 'remove' in request.POST: #if the user asked to remove another user or themselves this will run
                Remove = RemoveForm(request.POST or None)
                if Remove.is_valid():

                    removeduser = Remove.cleaned_data['removeUser'] #gets username of user who has to be removed
                    exitR = User.objects.filter(username = removeduser)
                    if not exitR: #checks if said user exists, if not returns error message
                        proper = 4
                        user = request.user
                        hive = get_object_or_404(Hive, pk=hive_id)
                        notes = Notes.objects.all()
                        persons = hive.user.all()
                        if not persons:
                            Hive.objects.filter(pk = hive_id).delete()

                            return redirect('/accounts/myHive')
                        board = MessageBoard.objects.all()
                        return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete' : Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})
                    if hive.user.filter(username = exitR.first().username): #removes user if they are in the hive
                        hive.user.remove(exitR.first())
                    elif not hive.user.filter(username = exitR.first().username): #if they aren't in the hive error will be given
                        proper = 2
                    user = request.user
                    hive = get_object_or_404(Hive, pk=hive_id) #gets hive we are in
                    notes = Notes.objects.all() #gets all notes to be filter
                    persons = hive.user.all() #gets all users in current hive
                    if not persons:
                        Hive.objects.filter(pk = hive_id).delete() #Should the last person in the Hive decide to leave the Hive, the entire Hive is deleted

                        return redirect('/accounts/myHive')
                    board = MessageBoard.objects.all() #gets all messageboard objects and they'll be filtered in the template for the ones that are connected to the Hive
                    return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete' : Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})

        if 'delete' in request.POST:
            Del = DeleteForm(request.POST or None) #filter
            if Del.is_valid():

                notes = Del.cleaned_data['notes_title'].lower() #forces user input to lower case for searching reasons
                hivepk1 = int(hive_id)
                print notes

                if not Notes.objects.filter(notes_title = notes, hivepk = hivepk1):
                    proper = 3

                Notes.objects.filter(notes_title = notes, hivepk = hivepk1).delete()

                user = request.user
                hive = get_object_or_404(Hive,pk = hive_id)
                notes = Notes.objects.all()
                persons = hive.user.all()
                board = MessageBoard.objects.all()
                return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete' : Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})

    user = request.user
    hive = get_object_or_404(Hive, pk=hive_id)
    notes = Notes.objects.all()
    persons = hive.user.all()
    board = MessageBoard.objects.all()


    if Comm.is_valid(): #MessageBoard Code, saves it and acts like all the other forms above
        new = Comm.save(commit = False)
        new.user = request.user
        new.hivepk = int(hive_id)
        new.save()
        print new.message
        user = request.user
        hive = get_object_or_404(Hive,pk = hive_id)
        notes = Notes.objects.all()
        persons = hive.user.all()
        board = MessageBoard.objects.all()
        return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete' : Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})



    return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form, 'dorm': Dorm, 'remove' : Remove, 'delete': Del, 'persons' : persons, 'proper': proper, 'board': board, 'message': Comm})

def DeleteUser(request):# User Deletion
    if not request.user.is_authenticated():
        return render(request, 'account/login.html')

    x = User.objects.get(username = request.user.username) #Searches for the user
    x.delete() #deletes the user
    return render(request, 'account/login.html')

# def SearchUserbase(request): #Searches Userbase
#     if not request.user.is_authenticated():
#         return render(request, 'account/login.html')
#     userS = SearchUserForm()
#     universityS = SearchUniversityForm()
#
#     if request.method == "POST": #Acts like the other forms.
#         userS = UserSearchForm(request.POST or None)
#         user = userS.cleaned_data['username'] #gets the username
#         userlist = User.objects.filter(username = user) #searches in the userbase for users with
#         univeristyS = SearchUniversityForm(request.POST or None) #Searches for the user and then
#         university = univeristyS.cleaned_data['university']
#         uniList = University.objects.filter(school = university)
#         x = User.objects.studentof(uniList.first())
#
#         if not userList:
#             if uniList:
#                 peeps = 1
#                 return render(request, 'account/search.html', {'userbox':userS, 'unibox': universityS,'university': uniList.first(), 'peeps': peeps, 'thepeople': x})
#         else:
#             if not uniList:
#                 peeps = 2
#                 return render(request, 'account/search.html', {'userbox':userS, 'unibox': universityS,'users': userList.first(),'peeps': peeps, 'thepeople': x})
#             else:
#                 peeps = 3
#                 return render(request, 'account/search.html', {'userbox':userS, 'unibox': universityS, 'university': uniList.first(), 'user': userList.first(), 'peeps': peeps, 'thepeople': x})
#
#     peeps = 0
#     return render(request, 'account/search.html', {'userbox':userS, 'unibox': universityS, 'peeps': peeps,})

def SearchUserbase(request): #Searching the userbase for inputted text
    if not request.user.is_authenticated():
        return render(request, 'account/login.html')
    userS = SearchUserForm()
    peeps = 0
    if request.method == "POST":
        userS = SearchUserForm(request.POST or None) #Gets input
        print userS
        user = userS.cleaned_data['username']  #gets data for searching
        userlist = User.objects.filter(username__contains=user) #checks if username contains the inputted data
        if not userlist: #Tells the user an error if nothing is found
            peeps = 1
        return render(request, 'account/search.html', {'userbox':userS, 'peeps': peeps, 'users': userlist})


    #else return the right thing.
    return render(request, 'account/search.html', {'userbox':userS, 'peeps': peeps})



#Twas meant to upload profile pics but it wasn't working out for us on a few levels, but we attempted it

# def profilepicupload(request):
#     pic = picForm(request.POST or None, request.FILES or None)
#     hive = get_object_or_404(Hive, pk=hive_id)
#     if form.is_valid():
#         pic = profilepics.notes_set.all()
#         pics = form.save(commit=False)
#         bio.user = user

#
#         user = request.user
#
#         return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form })
#
#     user = request.user
#     bio = get_object_or_404(Bio, pk=bio_id)
#
#     return render(request, 'account/detail.html', {'hive': hive, 'user': user, 'notes': notes, 'form': form })
