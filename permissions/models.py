
from django.db import models

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import ugettext_lazy as _


class Permission(models.Model):
    """A permission which can be granted to users/groups and objects.

    **Attributes:**

    name
        The unique name of the permission. This is displayed to users.

    codename
        The unique codename of the permission. This is used internal to
        identify a permission.

    content_types
        The content types for which the permission is active. This can be
        used to display only reasonable permissions for an object.
    """
    name = models.CharField(_(u"Name"), max_length=100, unique=True)
    codename = models.CharField(_(u"Codename"), max_length=100, unique=True)
    content_types = models.ManyToManyField(ContentType, verbose_name=_(u"Content Types"), blank=True, related_name="content_types")

    class Meta:
        app_label = "permissions"

    def __unicode__(self):
        return "%s (%s)" % (self.name, self.codename)


class ObjectPermission(models.Model):
    """Grants permission for a role and an content object (optional).

    **Attributes:**

    role
        The role for which the permission is granted.

    permission
        The permission which is granted.

    content
        The object for which the permission is granted.
    """
    role         = models.ForeignKey("Role",      verbose_name=_(u"Role"), blank=True, null=True, on_delete=models.SET_NULL)
    permission   = models.ForeignKey(Permission,  verbose_name=_(u"Permission"),                  on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, verbose_name=_(u"Content type"),                on_delete=models.CASCADE)
    content_id   = models.PositiveIntegerField(verbose_name=_(u"Content id"))
    content      = GenericForeignKey(ct_field="content_type", fk_field="content_id")

    class Meta:
        app_label = "permissions"

    def __unicode__(self):
        return "%s / %s / %s - %s" % (self.permission.name, self.role, self.content_type, self.content_id)


class ObjectPermissionInheritanceBlock(models.Model):
    """Blocks the inheritance for specific permission and object.

    **Attributes:**

    permission
        The permission for which inheritance is blocked.

    content
        The object for which the inheritance is blocked.
    """
    permission   = models.ForeignKey(Permission,  verbose_name=_(u"Permission"),   on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, verbose_name=_(u"Content type"), on_delete=models.CASCADE)
    content_id   = models.PositiveIntegerField(verbose_name=_(u"Content id"))
    content      = GenericForeignKey(ct_field="content_type", fk_field="content_id")

    class Meta:
        app_label = "permissions"

    def __unicode__(self):
        return "%s / %s - %s" % (self.permission, self.content_type, self.content_id)


class Role(models.Model):
    """A role gets permissions to do something. Principals (users and groups)
    can only get permissions via roles.

    **Attributes:**

    name
        The unique name of the role
    """
    name = models.CharField(max_length=100, unique=True)

    class Meta:
        app_label = "permissions"
        ordering = ("name", )

    def __unicode__(self):
        return self.name

    def add_principal(self, principal, content=None):
        """Addes the given principal (user or group) ot the Role.
        """
        import permissions.utils

        return permissions.utils.add_role(principal, self)

    def get_groups(self, content=None):
        """Returns all groups which has this role assigned. If content is given
        it returns also the local roles.
        """
        if content:
            ctype = ContentType.objects.get_for_model(content)
            prrs = PrincipalRoleRelation.objects.filter(role=self,
                content_id__in=(None, content.id),
                content_type__in=(None, ctype)).exclude(group=None)
        else:
            prrs = PrincipalRoleRelation.objects.filter(role=self,
            content_id=None, content_type=None).exclude(group=None)

        return [prr.group for prr in prrs]

    def get_users(self, content=None):
        """Returns all users which has this role assigned. If content is given
        it returns also the local roles.
        """
        if content:
            ctype = ContentType.objects.get_for_model(content)
            prrs = PrincipalRoleRelation.objects.filter(role=self,
                content_id__in=(None, content.id),
                content_type__in=(None, ctype)).exclude(user=None)
        else:
            prrs = PrincipalRoleRelation.objects.filter(role=self,
                content_id=None, content_type=None).exclude(user=None)

        return [prr.user for prr in prrs]


class PrincipalRoleRelation(models.Model):
    """A role given to a principal (user or group). If a content object is
    given this is a local role, i.e. the principal has this role only for this
    content object. Otherwise it is a global role, i.e. the principal has
    this role generally.

    user
        A user instance. Either a user xor a group needs to be given.

    group
        A group instance. Either a user xor a group needs to be given.

    role
        The role which is given to the principal for content.

    content
        The content object which gets the local role (optional).
    """

    """
    bos2_models_loaded = True

    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()
    except:
        bos2_models_loaded = False

    if bos2_models_loaded:

        from django.contrib.auth.models import Group

        user         = models.ForeignKey(User,        verbose_name=_(u"User"),         blank=True, null=True, on_delete=models.SET_NULL)
        group        = models.ForeignKey(Group,       verbose_name=_(u"Group"),        blank=True, null=True, on_delete=models.SET_NULL)
        role         = models.ForeignKey(Role,        verbose_name=_(u"Role"),                                on_delete=models.CASCADE)
        content_type = models.ForeignKey(ContentType, verbose_name=_(u"Content type"), blank=True, null=True, on_delete=models.SET_NULL)
        content_id = models.PositiveIntegerField(verbose_name=_(u"Content id"), blank=True, null=True)
        content = GenericForeignKey(ct_field="content_type", fk_field="content_id")
    """

    user = None

    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = models.ForeignKey(User, verbose_name=_("User"), blank=True, null=True, on_delete=models.SET_NULL)
    except:
        pass

    group = None

    try:
        group = models.ForeignKey(Group, verbose_name=_("Group"), blank=True, null=True, on_delete=models.SET_NULL)
    except:
        pass

    role = None

    try:
        role = models.ForeignKey(Role, verbose_name=_("Role"), on_delete=models.CASCADE)
    except:
        pass

    content_type = None

    try:
        content_type = models.ForeignKey(ContentType, verbose_name=_("Content type"), blank=True, null=True, on_delete=models.SET_NULL)
    except:
        pass

    content_id = None

    try:
        content_id = models.PositiveIntegerField(verbose_name=_("Content id"), blank=True, null=True)
    except:
        pass

    content = None

    try:
        content = GenericForeignKey(ct_field="content_type", fk_field="content_id")
    except:
        pass

    class Meta:
        app_label = "permissions"

    def __unicode__(self):
        principal = 'bos2_not_yet_loaded'
        my_role   = 'bos2_not_yet_loaded'

        if bos2_models_loaded:
            my_role = self.role

            if self.user:
                principal = self.user.username
            else:
                principal = self.group

        return "%s - %s" % (principal, my_role)

    def get_principal(self):
        """Returns the principal.
        """
        if bos2_models_loaded:
            return self.user or self.group
        else:
            return 'bos2_not_yet_loaded'

    def set_principal(self, principal):
        """Sets the principal.
        """
        if bos2_models_loaded:
            if isinstance(principal, User):
                self.user = principal
            else:
                self.group = principal

    if bos2_models_loaded:
        principal = property(get_principal, set_principal)
