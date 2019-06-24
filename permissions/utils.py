# django imports
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist

# permissions imports
from permissions.exceptions import Unauthorized

# Roles ######################################################################


def add_role(principal, role):
    """Adds a global role to a principal.

    **Parameters:**

    principal
        The principal (user or group) which gets the role added.

    role
        The role which is assigned.
    """
    user_class = get_user_model()
    from permissions.models import ObjectPermission
    from permissions.models import ObjectPermissionInheritanceBlock
    from permissions.models import Permission
    from permissions.models import PrincipalRoleRelation
    from permissions.models import Role

    if isinstance(principal, user_class):
        try:
            PrincipalRoleRelation.objects.get(user=principal, role=role, content_id=None, content_type=None)
        except PrincipalRoleRelation.DoesNotExist:
            PrincipalRoleRelation.objects.create(user=principal, role=role)
            return True
    else:
        try:
            PrincipalRoleRelation.objects.get(group=principal, role=role, content_id=None, content_type=None)
        except PrincipalRoleRelation.DoesNotExist:
            PrincipalRoleRelation.objects.create(group=principal, role=role)
            return True

    return False


def add_local_role(obj, principal, role):
    """Adds a local role to a principal.

    **Parameters:**

    obj
        The object for which the principal gets the role.

    principal
        The principal (user or group) which gets the role.

    role
        The role which is assigned.
    """
    user_class = get_user_model()
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import ObjectPermission
    from permissions.models import ObjectPermissionInheritanceBlock
    from permissions.models import Permission
    from permissions.models import PrincipalRoleRelation
    from permissions.models import Role

    ctype = ContentType.objects.get_for_model(obj)

    if isinstance(role, str):
        role = Role.objects.get(codename=role)

    if isinstance(principal, user_class):
        try:
            PrincipalRoleRelation.objects.get(user=principal, role=role, content_id=obj.id, content_type=ctype)
        except PrincipalRoleRelation.DoesNotExist:
            PrincipalRoleRelation.objects.create(user=principal, role=role, content=obj)
            return True
    else:
        try:
            PrincipalRoleRelation.objects.get(group=principal, role=role, content_id=obj.id, content_type=ctype)
        except PrincipalRoleRelation.DoesNotExist:
            PrincipalRoleRelation.objects.create(group=principal, role=role, content=obj)
            return True

    return False


def remove_role(principal, role):
    """Removes role from passed principal.

    **Parameters:**

    principal
        The principal (user or group) from which the role is removed.

    role
        The role which is removed.
    """
    user_class = get_user_model()
    from permissions.models import PrincipalRoleRelation
    try:
        if isinstance(principal, user_class):
            ppr = PrincipalRoleRelation.objects\
                .get(user=principal, role=role, content_id=None, content_type=None)
        else:
            ppr = PrincipalRoleRelation.objects\
                .get(group=principal, role=role, content_id=None, content_type=None)

    except PrincipalRoleRelation.DoesNotExist:
        return False
    else:
        ppr.delete()

    return True


def remove_local_role(obj, principal, role):
    """Removes role from passed object and principle.

    **Parameters:**

    obj
        The object from which the role is removed.

    principal
        The principal (user or group) from which the role is removed.

    role
        The role which is removed.
    """
    user_class = get_user_model()
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import PrincipalRoleRelation
    from permissions.models import Role

    if isinstance(role, str):
        role = Role.objects.get(codename=role)

    try:
        ctype = ContentType.objects.get_for_model(obj)

        if isinstance(principal, user_class):
            ppr = PrincipalRoleRelation.objects.get(
                user=principal, role=role, content_id=obj.id, content_type=ctype)
        else:
            ppr = PrincipalRoleRelation.objects.get(
                group=principal, role=role, content_id=obj.id, content_type=ctype)

    except PrincipalRoleRelation.DoesNotExist:
        return False
    else:
        ppr.delete()

    return True


def remove_roles(principal):
    """Removes all roles passed principal (user or group).

    **Parameters:**

    principal
        The principal (user or group) from which all roles are removed.
    """
    user_class = get_user_model()
    from permissions.models import PrincipalRoleRelation
    if isinstance(principal, user_class):
        ppr = PrincipalRoleRelation.objects.filter(
            user=principal, content_id=None, content_type=None)
    else:
        ppr = PrincipalRoleRelation.objects.filter(
            group=principal, content_id=None, content_type=None)

    if ppr:
        ppr.delete()
        return True
    else:
        return False


def remove_local_roles(obj, principal):
    """Removes all local roles from passed object and principal (user or
    group).

    **Parameters:**

    obj
        The object from which the roles are removed.

    principal
        The principal (user or group) from which the roles are removed.
    """
    user_class = get_user_model()
    from permissions.models import PrincipalRoleRelation
    from django.contrib.contenttypes.models import ContentType

    ctype = ContentType.objects.get_for_model(obj)

    if isinstance(principal, user_class):
        ppr = PrincipalRoleRelation.objects.filter(
            user=principal, content_id=obj.id, content_type=ctype)
    else:
        ppr = PrincipalRoleRelation.objects.filter(
            group=principal, content_id=obj.id, content_type=ctype)

    if ppr:
        ppr.delete()
        return True
    else:
        return False


def remove_local_roles_by_role(obj, roles):
    """Removes all local roles from roles list

    **Parameters:**

    obj
        The object from which the roles are removed.

    roles
        role or roles as codename/list of codenames or Role/list or Role objects
    """
    user_class = get_user_model()
    from permissions.models import PrincipalRoleRelation
    from permissions.models import Role
    from django.contrib.contenttypes.models import ContentType

    ctype = ContentType.objects.get_for_model(obj)

    if not isinstance(roles, (list, tuple)):
        roles = [roles]

    _local_roles = []
    for role in roles:
        if isinstance(role, str):
            role = Role.objects.get(codename=role)
        _local_roles.append(role)

    ppr = PrincipalRoleRelation.objects.filter(role__in=_local_roles, content_id=obj.id, content_type=ctype)

    if ppr:
        ppr.delete()
        return True
    else:
        return False


def get_roles(user, obj=None):
    """Returns *all* roles of the passed user.

    This takes direct roles and roles via the user's groups into account.

    If an object is passed local roles will also added. Then all local roles
    from all ancestors and all user's groups are also taken into account.

    This is the method to use if one want to know whether the passed user
    has a role in general (for the passed object).

    **Parameters:**

    user
        The user for which the roles are returned.

    obj
        The object for which local roles will returned.

    """
    role_ids = set()
    groups = user.groups.all()
    from permissions.models import PrincipalRoleRelation
    from permissions.models import Role
    # Gobal roles for user and the user's groups
    if groups:
        role_ids.update(PrincipalRoleRelation.objects.filter(content_id__isnull=True)
                                                     .filter(Q(user=user) | Q(group__in=groups))
                                                     .values_list('role', flat=True))
    else:
        role_ids.update(PrincipalRoleRelation.objects.filter(content_id__isnull=True, user=user)
                                                     .values_list('role', flat=True))

    # Local roles for user and the user's groups and all ancestors of the
    # passed object.
    while obj and not isinstance(obj, type):
        from django.contrib.contenttypes.models import ContentType

        ctype = ContentType.objects.get_for_model(obj)

        if groups:
            role_ids.update(PrincipalRoleRelation.objects.filter(content_type=ctype, content_id=obj.pk)
                                                         .filter(Q(user=user) | Q(group__in=groups))
                                                         .values_list('role_id', flat=True))
        else:
            role_ids.update(PrincipalRoleRelation.objects.filter(content_type=ctype, content_id=obj.pk, user=user)
                                                         .values_list('role_id', flat=True))

        try:
            obj = obj.get_parent_for_permissions()
        except AttributeError:
            obj = None

    return Role.objects.filter(pk__in=role_ids)


def get_global_roles(principal):
    """Returns *direct* global roles of passed principal (user or group).
    """
    user_class = get_user_model()
    from permissions.models import PrincipalRoleRelation
    if isinstance(principal, user_class):
        return [prr.role for prr in PrincipalRoleRelation.objects.filter(
            user=principal, content_id=None, content_type=None)]
    else:
        if isinstance(principal, Group):
            principal = (principal,)
        return [prr.role for prr in PrincipalRoleRelation.objects.filter(
            group__in=principal, content_id=None, content_type=None)]


def get_local_roles(obj, principal):
    """Returns *direct* local roles for passed principal and content object.
    """
    user_class = get_user_model()
    from permissions.models import PrincipalRoleRelation
    from django.contrib.contenttypes.models import ContentType

    ctype = ContentType.objects.get_for_model(obj)

    if isinstance(principal, user_class):
        return [prr.role for prr in PrincipalRoleRelation.objects.filter(
            user=principal, content_id=obj.id, content_type=ctype)]
    else:
        return [prr.role for prr in PrincipalRoleRelation.objects.filter(
            group=principal, content_id=obj.id, content_type=ctype)]


# Permissions ################################################################


def check_permission(obj, user, codename, roles=None):
    """Checks whether passed user has passed permission for passed obj.

    **Parameters:**

    obj
        The object for which the permission should be checked.

    codename
        The permission's codename which should be checked.

    user
        The user for which the permission should be checked.

    roles
        If given these roles will be assigned to the user temporarily before
        the permissions are checked.
    """
    if not has_permission(obj, user, codename, roles):
        raise Unauthorized("User '%s' doesn't have permission '%s' for object '/%s' (%s)." %
                           (user, codename, obj.slug, obj.__class__.__name__))


def grant_permission(obj, role, permission):
    """Grants passed permission to passed role. Returns True if the permission
    was able to be added, otherwise False.

    **Parameters:**

    obj
        The content object for which the permission should be granted.

    role
        The role for which the permission should be granted.

    permission
        The permission which should be granted. Either a permission
        object or the codename of a permission.
    """
    from permissions.models import ObjectPermission
    from permissions.models import Permission
    if not isinstance(permission, Permission):
        try:
            permission = Permission.objects.get(codename=permission)
        except Permission.DoesNotExist:
            return False
    from django.contrib.contenttypes.models import ContentType

    ct = ContentType.objects.get_for_model(obj)
    try:
        ObjectPermission.objects.get(role=role, content_type=ct, content_id=obj.id, permission=permission)
    except ObjectPermission.DoesNotExist:
        ObjectPermission.objects.create(role=role, content=obj, permission=permission)

    return True


def remove_permission(obj, role, permission):
    """Removes passed permission from passed role and object. Returns True if
    the permission has been removed.

    **Parameters:**

    obj
        The content object for which a permission should be removed.

    role
        The role for which a permission should be removed.

    permission
        The permission which should be removed. Either a permission object
        or the codename of a permission.
    """
    from permissions.models import ObjectPermission
    from permissions.models import Permission
    if not isinstance(permission, Permission):
        try:
            permission = Permission.objects.get(codename=permission)
        except Permission.DoesNotExist:
            return False
    from django.contrib.contenttypes.models import ContentType

    ct = ContentType.objects.get_for_model(obj)

    try:
        op = ObjectPermission.objects.get(role=role, content_type=ct, content_id=obj.id, permission=permission)
    except ObjectPermission.DoesNotExist:
        return False

    op.delete()
    return True


def has_permission(obj, user, codename, roles=None):
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import ObjectPermission
    from permissions.models import Permission
    """Checks whether the passed user has passed permission for passed object.

    **Parameters:**

    obj
        The object for which the permission should be checked.

    codename
        The permission's codename which should be checked.

    request
        The current request.

    roles
        If given these roles will be assigned to the user temporarily before
        the permissions are checked.
    """
    if user.is_superuser:
        return True

    if roles is None:
        roles = []

    if not user.is_anonymous:
        roles.extend(get_roles(user, obj))

    result = False

    obj_is_type = isinstance(obj, type)

    if obj:
        ctype = ContentType.objects.get_for_model(obj)


    # in case obj is none
    if obj is None or obj_is_type:
        # chceck if user/role has those permission
        filter = {
            'codename': codename,
            'roles_globals__in': roles
        }
        if obj_is_type:
            filter['content_types'] = ctype

        if Permission.objects.filter(**filter).count() > 0:
            result = True
    else:
        while obj is not None:
            if ObjectPermission.objects.filter(content_type=ctype,
                                                content_id=obj.id,
                                                role__in=roles,
                                                permission__codename=codename).count() > 0:
                result = True
                break

            if not is_inherited(obj, codename):
                result = False
                break

            try:
                obj = obj.get_parent_for_permissions()
                ctype = ContentType.objects.get_for_model(obj)
            except AttributeError:
                result = False
                break

    return result


# Inheritance ################################################################


def add_inheritance_block(obj, permission):
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import ObjectPermissionInheritanceBlock
    from permissions.models import Permission
    """Adds an inheritance for the passed permission on the passed obj.

    **Parameters:**

        permission
            The permission for which an inheritance block should be added.
            Either a permission object or the codename of a permission.
        obj
            The content object for which an inheritance block should be added.
    """
    if not isinstance(permission, Permission):
        try:
            permission = Permission.objects.get(codename=permission)
        except Permission.DoesNotExist:
            return False

    ct = ContentType.objects.get_for_model(obj)
    try:
        ObjectPermissionInheritanceBlock.objects.get(content_type=ct, content_id=obj.id, permission=permission)
    except ObjectPermissionInheritanceBlock.DoesNotExist:
        try:
            ObjectPermissionInheritanceBlock.objects.create(content=obj, permission=permission)
        except IntegrityError:
            return False
    return True


def remove_inheritance_block(obj, permission):
    """Removes a inheritance block for the passed permission from the passed
    object.

    **Parameters:**

    obj
        The content object for which an inheritance block should be added.

    permission
        The permission for which an inheritance block should be removed.
        Either a permission object or the codename of a permission.
    """
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import ObjectPermissionInheritanceBlock
    from permissions.models import Permission
    if not isinstance(permission, Permission):
        try:
            permission = Permission.objects.get(codename=permission)
        except Permission.DoesNotExist:
            return False

    ct = ContentType.objects.get_for_model(obj)
    try:
        opi = ObjectPermissionInheritanceBlock.objects.get(content_type=ct, content_id=obj.id, permission=permission)
    except ObjectPermissionInheritanceBlock.DoesNotExist:
        return False

    opi.delete()
    return True


def is_inherited(obj, codename):
    """Returns True if the passed permission is inherited for passed object.

    **Parameters:**

    obj
        The content object for which the permission should be checked.

    codename
        The permission which should be checked. Must be the codename of the
        permission.
    """
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import ObjectPermissionInheritanceBlock
    ctype = ContentType.objects.get_for_model(obj)
    try:
        ObjectPermissionInheritanceBlock.objects.get(content_type=ctype,
                                                     content_id=obj.id,
                                                     permission__codename=codename)
    except ObjectDoesNotExist:
        return True
    else:
        return False


def get_group(id_or_name):
    """Returns the group with passed id or name. If it not exists it returns
    None.
    """
    try:
        from django.contrib.auth.models import Group
        return Group.objects.get(pk=id_or_name)
    except (Group.DoesNotExist, ValueError):
        try:
            return Group.objects.get(name=id_or_name)
        except Group.DoesNotExist:
            return None


def get_role(id_or_name):
    """Returns the role with passed id or name. If it not exists it returns
    None.

    **Parameters:**

    id_or_name
        The id or the name of the role which should be returned.
    """
    from permissions.models import Role
    try:
        return Role.objects.get(pk=id_or_name)
    except (Role.DoesNotExist, ValueError):
        try:
            return Role.objects.get(codename=id_or_name)
        except Role.DoesNotExist:
            return None


def get_user(id_or_username):
    """Returns the user with passed id or username. If it not exists it returns
    None.

    **Parameters:**

    id_or_username
        The id or the username of the user which should be returned.
    """
    user_class = get_user_model()
    try:
        return user_class.objects.get(pk=id_or_username)
    except (user_class.DoesNotExist, ValueError):
        try:
            return user_class.objects.get(username=id_or_username)
        except user_class.DoesNotExist:
            return None


def has_group(user, group):
    """Returns True if passed user has passed group.
    """
    from django.contrib.auth.models import Group
    if isinstance(group, str):
        group = Group.objects.get(name=group)

    return group in user.groups.all()


def reset(obj):
    """Resets all permissions and inheritance blocks of passed object.
    """
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import ObjectPermission
    from permissions.models import ObjectPermissionInheritanceBlock

    ctype = ContentType.objects.get_for_model(obj)
    ObjectPermissionInheritanceBlock.objects.filter(content_id=obj.id, content_type=ctype).delete()
    ObjectPermission.objects.filter(content_id=obj.id, content_type=ctype).delete()


# Registering ################################################################


def register_permission(name, codename, ctypes=None):
    """Registers a permission to the framework. Returns the permission if the
    registration was successfully, otherwise False.

    **Parameters:**

    name
        The unique name of the permission. This is displayed to the customer.

    codename
        The unique codename of the permission. This is used internally to
        identify the permission.

    content_types
        The content type for which the permission is active. This can be
        used to display only reasonable permissions for an object. This
        must be a Django ContentType
    """
    from django.contrib.contenttypes.models import ContentType
    from permissions.models import Permission
    if ctypes is None:
        ctypes = []

    # Permission with same codename and/or name must not exist.
    if Permission.objects.filter(Q(name=name) | Q(codename=codename)):
        return False

    p = Permission.objects.create(name=name, codename=codename)

    ctypes = [ContentType.objects.get_for_model(ctype) for ctype in ctypes]
    if ctypes:
        p.content_types = ctypes
        p.save()

    return p


def unregister_permission(codename):
    """Unregisters a permission from the framework

    **Parameters:**

    codename
        The unique codename of the permission.
    """
    from permissions.models import Permission
    try:
        permission = Permission.objects.get(codename=codename)
    except Permission.DoesNotExist:
        return False
    permission.delete()
    return True


def register_role(name):
    """Registers a role with passed name to the framework. Returns the new
    role if the registration was successfully, otherwise False.

    **Parameters:**

    name
        The unique role name.
    """
    from permissions.models import Role
    role, created = Role.objects.get_or_create(name=name)
    if created:
        return role
    else:
        return False


def unregister_role(name):
    """Unregisters the role with passed name.

    **Parameters:**

    name
        The unique role name.
    """
    from permissions.models import Role
    try:
        role = Role.objects.get(name=name)
    except Role.DoesNotExist:
        return False

    role.delete()
    return True


def register_group(name):
    """Registers a group with passed name to the framework. Returns the new
    group if the registration was successfully, otherwise False.

    Actually this creates just a default Django Group.

    **Parameters:**

    name
        The unique group name.
    """
    from django.contrib.auth.models import Group
    group, created = Group.objects.get_or_create(name=name)
    if created:
        return group
    else:
        return False


def unregister_group(name):
    """Unregisters the group with passed name. Returns True if the
    unregistration was succesfull otherwise False.

    Actually this deletes just a default Django Group.

    **Parameters:**

    name
        The unique role name.
    """
    try:
        from django.contrib.auth.models import Group
        group = Group.objects.get(name=name)
    except Group.DoesNotExist:
        return False

    group.delete()
    return True
