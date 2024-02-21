import random
import uuid
from datetime import timedelta, datetime
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

ORDINARY_USER, MANAGER, ADMIN = ("ordinary_user", 'manager', 'admin')
PHONE_STEP, CODE_STEP, DONE_STEP = ('phone_step', 'code_step', 'done_step')
MALE, FEMALE = ('male', 'female')
PHONE_EXPIRE = 2
VIA_PHONE = 'via_phone'

class User(AbstractUser, models.Model):
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (MANAGER, MANAGER),
        (ADMIN, ADMIN)
    )

    AUTH_STATUS = (
        (PHONE_STEP, PHONE_STEP),
        (CODE_STEP, CODE_STEP),
        (DONE_STEP, DONE_STEP)
    )

    GENDER = (
        (MALE, MALE),
        (FEMALE, FEMALE)
    )

    class AUTH_TYPE(models.TextChoices):
        VIA_PHONE, VIA_PHONE

    id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False, primary_key=True)
    user_roles = models.CharField(max_length=31, choices=USER_ROLES, default=ORDINARY_USER)
    auth_status = models.CharField(max_length=31, choices=AUTH_STATUS, default=PHONE_STEP)
    auth_type = models.CharField(max_length=31, choices=AUTH_TYPE, default=VIA_PHONE)
    email = models.EmailField(null=True, blank=True, unique=True)
    phone_number = models.CharField(max_length=13, unique=True)
    gender = models.CharField(max_length=6, choices=GENDER, null=True, blank=True)
    date_of_birth = models.DateTimeField(null=True, blank=True)
    photo = models.ImageField(upload_to='user_photos/', null=True, blank=True,
                              validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'heic', 'heif'])])
    active_time = models.DateTimeField(default=timezone.now)
    create_time = models.DateTimeField(auto_now_add=True)
    update_time = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.username

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def create_verify_code(self):
        code = "".join([str(random.randint(0, 10000) % 10) for _ in range(6)])
        UserConfirmation.objects.create(
            user_id=self.id,
            code=code
        )
        return code


    def check_username(self):
        if not self.username:
            temp_username = f'commerce-{uuid.uuid4().__str__().split("-")[-1]}'
            while User.objects.filter(username=temp_username):
                temp_username = f"{temp_username}{random.randint(0,100)}"
            self.username = temp_username

    def check_email(self):
        if not self.email:
            temp_email = f'commerce{uuid.uuid4().__str__().split("-")[-1]}@gmail.com'
            self.email = temp_email.lower()

    def check_pass(self):
        if not self.password:
            temp_password = f'password-{uuid.uuid4().__str__().split("-")[-1]}'
            self.password = temp_password

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh_token": str(refresh)
        }

    def save(self, *args, **kwargs):
        self.clean()
        super(User, self).save(*args, **kwargs)

    def clean(self):
        self.check_email()
        self.check_username()
        self.check_pass()
        self.hashing_password()


class UserConfirmation(models.Model):
    code = models.CharField(max_length=6)
    user = models.ForeignKey('users.User', models.CASCADE, related_name='verify_codes')
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)
    objects = models.Manager()
    active_time = models.DateTimeField(default=timezone.now)
    create_time = models.DateTimeField(auto_now_add=True)
    update_time = models.DateTimeField(auto_now=True)
    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        self.expiration_time = datetime.now() + timedelta(minutes=PHONE_EXPIRE)
        super(UserConfirmation, self).save(*args, **kwargs)


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
    active_time = models.DateTimeField(default=timezone.now)
    create_time = models.DateTimeField(auto_now_add=True)
    update_time = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.email