.. _roles:

角色系统概述
=======================

PostgREST旨在将数据库保持在API安全性的中心。 所有授权都通过数据库角色和权限进行。 PostgREST的工作是**验证**请求 - 即验证客户端是否是他们所说的 - 然后让数据库**授权**客户端操作。

验证序列
-----------------------

the **authenticator**, **anonymous** and **user** roles. 
PostgREST使用三种类型的角色，**身份验证器**，**匿名**和**用户**角色。 数据库管理员创建这些角色并配置PostgREST以使用它们。

.. image:: _static/security-roles.png

The authenticator
应该创建身份验证器：代码：`NOINHERIT`并在数据库中配置以获得非常有限的访问权限。 它是一个变色龙，其工作是“成为”其他用户来为经过身份验证的HTTP请求提供服务。 下图显示了服务器如何处理身份验证。 如果auth成功，它将切换到请求指定的用户角色，否则将切换到匿名角色。

.. image:: _static/security-anon-choice.png

Here are the technical details. We use `JSON Web Tokens <http://jwt.io/>`_ to authenticate API requests.您可能还记得JWT包含加密签名声明的列表。 所有索赔都是允许的，但PostgREST特别关注一个名为角色role的声明。

.. code:: json

  {
    "role": "user123"
  }

当请求包含具有角色声明的有效JWT时，PostgREST将在HTTP请求期间切换到具有该名称的数据库角色。

.. code:: sql

  SET LOCAL ROLE user123;

请注意，通过先前的操作，数据库管理员必须允许身份验证者角色来切换到此用户

.. code:: sql

  GRANT user123 TO authenticator;

如果客户端不包含JWT（或没有角色声明的JWT），则PostgREST将切换到匿名角色，该角色的实际数据库特定名称（如使用验证者角色的名称）在PostgREST服务器配置文件中指定。 数据库管理员必须正确设置匿名角色权限，以防止匿名用户查看或更改他们不应该访问的内容。

用户和组
----------------

PostgreSQL使用角色的概念管理数据库访问权限。 可以将角色role视为数据库用户或一组数据库用户，具体取决于角色的设置方式。

每个 Web 用户的角色
~~~~~~~~~~~~~~~~~~~~~~~

PostgREST可以适应任何一个观点。 如果您将角色视为单个用户，那么上述基于JWT的角色切换可以完成您所需的大部分工作。 当经过身份验证的用户发出请求时，PostgREST将切换到该用户的角色，除了限制查询之外，SQL还可以通过：code：`current_user`变量使用该角色。

您可以使用行级安全性灵活地限制当前用户的可见性和访问权限。 以下是来自Tomas Vondra的示例<http://blog.2ndquadrant.com/application-users-vs-row-level-security/>`_，这是一个存储用户之间发送的消息的聊天表。 用户可以在其中插入行以向其他用户发送消息，并查询它以查看其他用户发送给他们的消息。

.. code:: sql

  CREATE TABLE chat (
    message_uuid    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_time    TIMESTAMP NOT NULL DEFAULT now(),
    message_from    NAME      NOT NULL DEFAULT current_user,
    message_to      NAME      NOT NULL,
    message_subject VARCHAR(64) NOT NULL,
    message_body    TEXT
  );

我们希望实施一项政策，确保用户只能看到他发送或打算发给他的那些消息。 此外，我们还希望阻止用户使用其他人的姓名伪造message_from列。

PostgreSQL（9.5及更高版本）允许我们使用行级安全性设置此策略：

.. code:: sql

  CREATE POLICY chat_policy ON chat
    USING ((message_to = current_user) OR (message_from = current_user))
    WITH CHECK (message_from = current_user)

访问生成的聊天表API端点的任何人都将看到他们应该准确的行，而无需我们需要自定义命令式服务器端编码。

Web 用户共享角色
~~~~~~~~~~~~~~~~~~~~~~

或者，数据库角色可以代表组而不是个别用户（或个别除外）。 您可以选择Web应用程序的所有已登录用户共享同一个webuser角色。 您可以通过在JWT中包含额外声明来甄别/排除具体某个用户，例如通过电子邮件。

.. code:: json

  {
    "role": "webuser",
    "email": "john@doe.com"
  }

SQL代码可以通过PostgREST按请求设置的GUC变量访问声明。 例如，要获取电子邮件声明，请调用此函数：

.. code:: sql

  current_setting('request.jwt.claim.email', true)

This allows JWT generation services to include extra information and your database code to react to it. For instance the RLS example could be modified to use this current_setting rather than current_user.  The second 'true' argument tells current_setting to return NULL if the setting is missing from the current configuration.

混合用户组角色
~~~~~~~~~~~~~~~~~~~~~~~

拥有许多数据库角色没有性能损失，尽管角色是按群集命名而不是按数据库命名，因此可能容易在数据库中发生冲突。 如果需要，您可以自由为Web应用程序中的每个用户分配新角色。 您可以混合组和单个角色策略。 例如，我们仍然可以拥有一个webuser角色和从中继承的个人用户：

.. code:: sql

  CREATE ROLE webuser NOLOGIN;
  -- grant this role access to certain tables etc

  CREATE ROLE user000 NOLOGIN;
  GRANT webuser TO user000;
  -- now user000 can do whatever webuser can

  GRANT user000 TO authenticator;
  -- allow authenticator to switch into user000 role
  -- (the role itself has nologin)

.. _custom_validation:

自定义验证
-----------------

PostgREST通过代码：`exp`声明令牌到期，拒绝过期的令牌。 但是，它不会强制执行任何额外的约束。 额外约束的一个示例是立即撤销对特定用户的访问。 配置文件参数：code：`pre-request`指定在验证者切换到新角色之后和主查询本身运行之前立即调用的存储过程。

这是一个例子。 在配置文件中指定存储过程：

.. code:: ini

  pre-request = "public.check_user"

在该函数中，您可以运行任意代码来检查请求，并根据需要引发异常以阻止它。

.. code:: sql

  CREATE OR REPLACE FUNCTION check_user() RETURNS void
    LANGUAGE plpgsql
    AS $$
  BEGIN
    IF current_user = 'evil_user' THEN
      RAISE EXCEPTION 'No, you are evil'
        USING HINT = 'Stop being so evil and maybe you can log in';
    END IF;
  END
  $$;

客户端 Auth
===========

要进行经过身份验证的请求，客户端必须包含：code：`Authorization` HTTP标头，其值为：code：`Bearer <jwt>`。 例如：

.. code:: http

  GET /foo HTTP/1.1
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiamRvZSIsImV4cCI6MTQ3NTUxNjI1MH0.GYDZV3yM0gqvuEtJmfpplLBXSGYnke_Pvnl0tbKAjB4

JWT Generation
--------------

您可以从数据库内部或通过外部服务创建有效的JWT。 每个令牌都使用秘密密码加密签名 - 签名者和验证者共享秘密。 因此，与PostgREST服务器共享密码的任何服务都可以创建有效的JWT。 （PostgREST目前仅支持HMAC-SHA256签名算法。）

JWT from SQL
~~~~~~~~~~~~

您可以使用`pgjwt extension <https://github.com/michelp/pgjwt>`_在SQL中创建JWT令牌。 它很简单，只需要pgcrypto。 如果您使用的是不支持安装新扩展的Amazon RDS等环境，您仍然可以在pgjwt中手动运行SQL，从而创建您需要的功能。

接下来编写一个返回令牌的存储过程。 下面的一个返回一个带有硬编码角色的令牌，该角色在发布后五分钟到期。 请注意，此函数也有一个硬编码的密码。

.. code:: sql

  CREATE TYPE jwt_token AS (
    token text
  );

  CREATE FUNCTION jwt_test() RETURNS public.jwt_token
      LANGUAGE sql
      AS $$
    SELECT sign(
      row_to_json(r), 'mysecret'
    ) AS token
    FROM (
      SELECT
        'my_role'::text as role,
        extract(epoch from now())::integer + 300 AS exp
    ) r;
  $$;


PostgREST通过对`/rpc/jwt_test`进行POST请求，来向客户端暴露此函数（函数都是这样/rpc定义访问）。

.. note::

 要避免对存储过程中的密钥进行硬编码，请将其另存为数据库的属性。

  .. code-block:: postgres

    -- run this once
    ALTER DATABASE mydb SET "app.jwt_secret" TO '!!secret!!';

    -- then all functions can refer to app.jwt_secret
    SELECT sign(
      row_to_json(r), current_setting('app.jwt_secret')
    ) AS token
    FROM ...

JWT from Auth0
~~~~~~~~~~~~~~

像Auth0 <https://auth0.com/>`_这样的外部服务可以将OAuth从Github，Twitter，Google等转变为适合PostgREST的JWT。 Auth0还可以处理电子邮件注册和密码重置流程。

要使用Auth0，请将其客户端密钥复制到PostgREST配置文件中，如下所示：code：`jwt-secret`。 （旧式的Auth0秘密是Base64编码的。对于这些秘密设置：代码：`secret-is-base64` to：code：`true`，或者只刷新Auth0秘密。）你可以在客户端设置中找到秘密。 Auth0管理控制台。

我们的代码需要JWT中的数据库角色。要添加它，您需要将数据库角色保存在Auth0`app metadata <https://auth0.com/docs/rules/metadata-in-rules>`_中。然后，您将需要编写一个规则，该规则将从用户元数据中提取角色，并在我们的用户对象的有效负载中包含：code：`role`声明。然后，在您的Auth0Lock代码中，在您的`scope param <https://auth0.com/docs/libraries/lock/v10/sending-authentication-parameters#scope-string->中包含：code：`role`声明。

.. code:: javascript

  // Example Auth0 rule
  function (user, context, callback) {
    user.app_metadata = user.app_metadata || {};
    user.role = user.app_metadata.role;
    callback(null, user, context);
  }


.. code:: javascript

  // Example using Auth0Lock with role claim in scope
  new Auth0Lock ( AUTH0_CLIENTID, AUTH0_DOMAIN, {
    container: 'lock-container',
    auth: {
      params: { scope: 'openid role' },
      redirectUrl: FQDN + '/login', // Replace with your redirect url
      responseType: 'token'
    }
  })

JWT 安全
~~~~~~~~~~~~

对于使用JWT，至少有三种常见的批评：1）针对标准本身，2）反对使用具有已知安全漏洞的库，以及3）反对使用JWT进行Web会话。我们将简要解释每个批评，PostgREST如何处理它，并为适当的用户操作提供建议。

关于“JWT标准<https://tools.ietf.org/html/rfc7519>`_的批评在网上其他地方详细说明<https://paragonie.com/blog/2017/03/jwt- JSON-Web的标记 - 是 - 坏标准是，每个人，应该规避>`_。 PostgREST最相关的部分是所谓的：代码：`alg = none`问题。一些实现JWT的服务器允许客户端选择用于签署JWT的算法。在这种情况下，攻击者可以将算法设置为：code：`none`，根本不需要任何签名，并获得未经授权的访问。但是，PostgREST的当前实现不允许客户端在HTTP请求中设置签名算法，从而使此攻击无关紧要。对标准的批评是它需要执行：code：`alg = none`。

对JWT库的批评仅通过它使用的库与PostgREST相关。如上所述，不允许客户端在HTTP请求中选择签名算法会消除最大的风险。如果服务器使用RSA等非对称算法进行签名，则可能会发生另一种更微妙的攻击。这再次与PostgREST无关，因为它不受支持。好奇的读者可以在本文<https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/>`_中找到更多信息。有关在API客户端中使用的高质量库的建议，请参阅`jwt.io <https://jwt.io/>`_。

最后一种批评的重点是滥用JWT来维护网络会话。基本建议是“停止使用JWT进行会话<http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/>`_因为大多数（如果不是全部） ，当你做的时候出现的问题的解决方案，``不工作<http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why - 您的溶液-犯规工作/>`_。链接的文章深入讨论了这些问题，但问题的实质是JWT并非设计为客户端存储的安全和有状态单元，因此不适合会话管理。

PostgREST主要使用JWT进行身份验证和授权，并鼓励用户也这样做。对于Web会话，使用基于HTTPS的cookie非常好，并且可以通过标准Web框架进行良好的迎合。
.. _ssl:

SSL
---

PostgREST旨在做好一件事：为PostgreSQL数据库添加HTTP接口。 为了保持代码小而集中，我们不实现SSL。 使用像NGINX这样的反向代理来添加它，“这里是如何<https://nginx.org/en/docs/http/configuring_https_servers.html>`_。 请注意，像Heroku这样的某些平台即服务也会在其负载均衡器中自动添加SSL。

架构隔离
================

PostgREST实例配置为公开服务器配置文件中指定的单个模式的所有表，视图和存储过程。 这意味着私有数据或实现细节可以进入私有模式，并且对HTTP客户端是不可见的。 然后，您可以公开视图和存储过程，从而将内部细节与外部世界隔离开来。 它使代码更容易重构，并提供了一种自然的方式来进行API版本控制。 有关使用公共视图包装私有表的示例，请参阅下面的：ref：`public_ui`部分。

SQL 用户管理
===================

存储用户和密码
---------------------------

如上所述，外部服务可以提供用户管理并使用JWT与PostgREST服务器协调。 也可以完全通过SQL支持登录。 这是一项相当多的工作，所以准备好了。

下表，函数和触发器将存在于：code：`basic_auth`模式中，您不应在API中公开公开。 公共视图和函数将存在于不同的模式中，该模式在内部引用此内部信息。

首先，我们需要一个表来跟踪我们的用户：

.. code:: sql

  -- 我们将内容置于basic_auth模式中，
  -- 以将其隐藏在公共视图中。 
  -- 某些公共过程/视图将引用内部的帮助程序和表。
  create schema if not exists basic_auth;

  create table if not exists
  basic_auth.users (
    email    text primary key check ( email ~* '^.+@.+\..+$' ),
    pass     text not null check (length(pass) < 512),
    role     name not null check (length(role) < 512)
  );

我们希望该角色role是实际数据库角色的外键，但是PostgreSQL不支持对：code：`pg_roles`表的这些约束。 我们将使用触发器手动强制执行它。

.. code:: plpgsql

  create or replace function
  basic_auth.check_role_exists() returns trigger
    language plpgsql
    as $$
  begin
    if not exists (select 1 from pg_roles as r where r.rolname = new.role) then
      raise foreign_key_violation using message =
        'unknown database role: ' || new.role;
      return null;
    end if;
    return new;
  end
  $$;

  drop trigger if exists ensure_user_role_exists on basic_auth.users;
  create constraint trigger ensure_user_role_exists
    after insert or update on basic_auth.users
    for each row
    execute procedure basic_auth.check_role_exists();

接下来，我们将使用pgcrypto扩展和触发器来保密密码：code：`users`表。

.. code:: plpgsql

  create extension if not exists pgcrypto;

  create or replace function
  basic_auth.encrypt_pass() returns trigger
    language plpgsql
    as $$
  begin
    if tg_op = 'INSERT' or new.pass <> old.pass then
      new.pass = crypt(new.pass, gen_salt('bf'));
    end if;
    return new;
  end
  $$;

  drop trigger if exists encrypt_pass on basic_auth.users;
  create trigger encrypt_pass
    before insert or update on basic_auth.users
    for each row
    execute procedure basic_auth.encrypt_pass();

使用该表，我们可以帮助检查加密列的密码。 如果电子邮件和密码正确，它将返回用户的数据库角色。

.. code:: plpgsql

  create or replace function
  basic_auth.user_role(email text, pass text) returns name
    language plpgsql
    as $$
  begin
    return (
    select role from basic_auth.users
     where users.email = user_role.email
       and users.pass = crypt(user_role.pass, users.pass)
    );
  end;
  $$;

.. _public_ui:

Public 用户界面
---------------------

在上一节中，我们创建了一个用于存储用户信息的内部表。 在这里，我们创建一个登录函数，它接受一个电子邮件地址和密码，如果凭据与内部表中的用户匹配，则返回JWT。

登录
~~~~~~

如``JWT from SQL`_中所述，我们将在登录函数中创建一个JWT。 请注意，您需要将此示例中硬编码的密钥调整为您选择的安全密钥。

.. code:: plpgsql

  create or replace function
  login(email text, pass text) returns basic_auth.jwt_token
    language plpgsql
    as $$
  declare
    _role name;
    result basic_auth.jwt_token;
  begin
    -- check email and password
    select basic_auth.user_role(email, pass) into _role;
    if _role is null then
      raise invalid_password using message = 'invalid user or password';
    end if;

    select sign(
        row_to_json(r), 'mysecret'
      ) as token
      from (
        select _role as role, login.email as email,
           extract(epoch from now())::integer + 60*60 as exp
      ) r
      into result;
    return result;
  end;
  $$;

调用此函数的API请求如下所示：

.. code:: http

  POST /rpc/login HTTP/1.1

  { "email": "foo@bar.com", "pass": "foobar" }

响应看起来像下面的代码段。 尝试在`jwt.io <https://jwt.io/>`_解码令牌。 （它的编码带有以下秘密：代码：`mysecret`，如上面的SQL代码中所指定的。你将会在你的应用程序中更改这个秘密！）

.. code:: json

  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImZvb0BiYXIuY29tIiwicm9sZSI6ImF1dGhvciJ9.fpf3_ERi5qbWOE5NPzvauJgvulm0zkIG9xSm2w5zmdw"
  }

权限
~~~~~~~~~~~

您的数据库角色需要访问模式，表，视图和函数才能为HTTP请求提供服务。 回想一下“角色系统概述”_，PostgREST使用特殊角色来处理请求，即身份验证者和匿名角色。 以下是允许匿名用户创建帐户并尝试登录的权限示例。

.. code:: sql

  -- 名称“anon”和“authenticator”是可配置的
  -- 而不是关键词，我们只是为了清晰起见而选择它们
  create role anon;
  create role authenticator noinherit;
  grant anon to authenticator;

  grant usage on schema public, basic_auth to anon;
  grant select on table pg_authid, basic_auth.users to anon;
  grant execute on function login(text,text) to anon;

您可能会担心，匿名用户可以从：code：`basic_auth.users`表中读取所有内容。 但是，此表不适用于直接查询，因为它位于单独的架构中。 匿名角色需要访问，因为public：code：`users`视图使用调用用户的权限读取基础表。 但我们已确保视图正确限制对敏感信息的访问。

