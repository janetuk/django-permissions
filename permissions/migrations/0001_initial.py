# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('contenttypes', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ObjectPermission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('content_id', models.PositiveIntegerField(verbose_name='Content id')),
                ('content_type', models.ForeignKey(verbose_name='Content type', to='contenttypes.ContentType')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ObjectPermissionInheritanceBlock',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('content_id', models.PositiveIntegerField(verbose_name='Content id')),
                ('content_type', models.ForeignKey(verbose_name='Content type', to='contenttypes.ContentType')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=100, verbose_name='Name')),
                ('codename', models.CharField(unique=True, max_length=100, verbose_name='Codename')),
                ('content_types', models.ManyToManyField(related_name=b'content_types', null=True, verbose_name='Content Types', to='contenttypes.ContentType', blank=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='PrincipalRoleRelation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('content_id', models.PositiveIntegerField(null=True, verbose_name='Content id', blank=True)),
                ('content_type', models.ForeignKey(verbose_name='Content type', blank=True, to='contenttypes.ContentType', null=True)),
                ('group', models.ForeignKey(verbose_name='Group', blank=True, to='auth.Group', null=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=100)),
                ('codename', models.CharField(unique=True, max_length=100, verbose_name='Codename')),
                ('global_permissions', models.ManyToManyField(related_name=b'roles_globals', null=True, verbose_name='Global permissions', to='permissions.Permission', blank=True)),
            ],
            options={
                'ordering': ('name',),
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='principalrolerelation',
            name='role',
            field=models.ForeignKey(verbose_name='Role', to='permissions.Role'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='principalrolerelation',
            name='user',
            field=models.ForeignKey(verbose_name='User', blank=True, to=settings.AUTH_USER_MODEL, null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='objectpermissioninheritanceblock',
            name='permission',
            field=models.ForeignKey(verbose_name='Permission', to='permissions.Permission'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='objectpermission',
            name='permission',
            field=models.ForeignKey(verbose_name='Permission', to='permissions.Permission'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='objectpermission',
            name='role',
            field=models.ForeignKey(verbose_name='Role', blank=True, to='permissions.Role', null=True),
            preserve_default=True,
        ),
    ]
