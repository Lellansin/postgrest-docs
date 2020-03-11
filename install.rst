可执行文件
==============

[ `下载页 <https://github.com/begriffs/postgrest/releases/latest>`_ ]

下载页面具有 Mac OS X、Windows 和几个 Linux 发行版的预编译文件。解压之后可以运行可执行文件加 :code:`--help` 标志来查看使用说明:

.. code-block:: bash

  # 解压 tar 包 (available at https://github.com/begriffs/postgrest/releases/latest)

  $ tar Jxf postgrest-[version]-[platform].tar.xz

  # 尝试运行
  $ ./postgrest --help

  # You should see a usage help message

Homebrew
========

在 Mac 上你可以使用 Homebrew 来安装 PostgREST

.. code-block:: bash

  # 确保 brew 是最新的
  brew update

  # 检查 brew 的 setup 有没问题
  brew doctor

  # 安装 postgrest
  brew install postgrest

该命令会自动将 PostgreSQL 当做依赖安装. 该过程往往需要长达15分钟才能安装软件包及其依赖。

安装完成后，该工具会被添加到 $PATH 中，你可以在任意位置使用：

.. code-block:: bash

  postgrest --help

PostgreSQL 依赖
=====================

要使用 PostgREST 您将需要安装数据库（PostgreSQL 9.3 或更高版本）。 您可以使用像 Amazon `RDS <https://aws.amazon.com/rds/>`_ 这样的东西，但是在本地安装本身比较便宜，更便于开发。

* `OS X 说明 <http://exponential.io/blog/2015/02/21/install-postgresql-on-mac-os-x-via-brew/>`_
* `Ubuntu 14.04 说明 <https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-ubuntu-14-04>`_
* `Windows 安装包 <http://www.enterprisedb.com/products-services-training/pgdownload#windows>`_

.. _build_source:

源代码编译
=================

.. note::

  我们不建议在 **Alpine Linux** 上构建和使用 PostgREST，因为在该平台有过 GHC 内存泄漏的报告。

当您的系统没有预构建的可执行文件时，可以从源代码构建项目。如果您想帮助开发，您还需要这种操作操作：`安装 Stack <https://github.com/commercialhaskell/stack>`_ 。它将在您的系统上安装任何必要的 Haskell 依赖。

* `安装 Stack <http://docs.haskellstack.org/en/stable/README.html#how-to-install>`_
* 安装依赖库

  =====================  =======================================
  Operating System       Dependencies
  =====================  =======================================
  Ubuntu/Debian          libpq-dev, libgmp-dev
  CentOS/Fedora/Red Hat  postgresql-devel, zlib-devel, gmp-devel
  BSD                    postgresql95-server
  OS X                   postgresql, gmp
  =====================  =======================================

* 构建并安装

  .. code-block:: bash

    git clone https://github.com/begriffs/postgrest.git
    cd postgrest

    # adjust local-bin-path to taste
    stack build --install-ghc --copy-bins --local-bin-path /usr/local/bin

.. note::

   如果你构建失败，而且你的系统只有不到 1GB 内存，尝试添加一个 swap 文件。

* 检查安装是否成功: :code:`postgrest --help`.

PostgREST 测试套件
--------------------

创建测试库
~~~~~~~~~~~~~~~~~~~~~~~~~~

为了正确运行postgrest进行测试，首先需要创建一个数据库。为此，请使用:code:`test/`目录下为测试准备的建库脚本:code:`create_test_database`。

脚本需要以下参数：

.. code:: bash

  test/create_test_db connection_uri database_name [test_db_user] [test_db_user_password]

使用`connection URI <https://www.postgresql.org/docs/current/static/libpq-connect.html#AEN45347>`_ 去指定数据库用户、密码、主机以及端口。不要在数据库连接URI中提供数据库。用于连接的Postgres必须拥有能够创建新数据库的能力。

脚本中的:code:`database_name`参数，是将要连接到的数据库名称。如果服务器上已存在同名数据库，则脚本将删除该数据库，然后进行重新创建。

如果使用指定的数据库用户进行堆栈测试。每次测试运行后，用户都将获得重置数据库所需的权限。

如果未指定用户，脚本将会生成角色名:code:`postgrest_test_`，并以所选数据库名作为后缀，而且还会自动生成一个随机密码。

如果使用一个已经存在的用户来进行测试连接，那么还需要指定该用户的密码。

该脚本将返回测试过程中使用的数据uri - 该uri与将在生产中使用的配置文件参数:code:`db-uri`相对应。

生成用户和密码允许创建数据库并对任何postgres服务器运行测试，而无需对服务器进行任何修改。（例如，允许没有密码的帐户或设置信任身份验证，或要求服务器位于运行测试的同一本地主机上）。

运行测试
~~~~~~~~~~~~~~~~~

为了运行测试，必须在环境变量中提供数据库的uri信息，对应的变量名称为:code:`POSTGREST_TEST_CONNECTION`。

通常情况下，创建数据库与运行测试命令会在同一命令行中执行，并且使用超级用户`postgres`：

.. code:: bash

  POSTGREST_TEST_CONNECTION=$(test/create_test_db "postgres://postgres:pwd@database-host" test_db) stack test

在同一数据库中重复运行时，应该导出数据库连接变量信息：

.. code:: bash

  export POSTGREST_TEST_CONNECTION=$(test/create_test_db "postgres://postgres:pwd@database-host" test_db)
  stack test
  stack test
  ...

如果环境变量为空或未指定，那么测试的运行程序将会默认连接uri

.. code:: bash

  postgres://postgrest_test@localhost/postgrest_test

上述连接假定测试的服务器在本地:code:`localhost:code:`，并且数据库用户`postgrest_test`没有指定密码和同名的数据库。

销毁数据库
~~~~~~~~~~~~~~~~~~~~~~~

测试完成之后，测试数据库将会被保留，同时还会在postgres服务器上创建四个新角色。如果需要永久性删除已创建的数据库和角色，请使用与创建数据库相同的超级用户角色执行脚本:code:`test/delete_test_database`：

.. code:: bash

  test/destroy_test_db connection_uri database_name

使用 Docker 测试
~~~~~~~~~~~~~~~~~~~

为了简化连接非本地环境PostgreSQL的测试环境设置，可以使用一种非常简洁的方式，在docker中创建一个PostgreSQL。

例如，如果是在mac上做本地开发（且已经安装了Docker服务），可执行以下命令进行安装：

.. code:: bash

  $ docker run --name db-scripting-test -e POSTGRES_PASSWORD=pwd -p 5434:5432 -d postgres
  $ POSTGREST_TEST_CONNECTION=$(test/create_test_db "postgres://postgres:pwd@localhost:5434" test_db) stack test

此外，如果通过创建docker容器运行来运行堆栈测试（对于GHC低于8.0.1的MacOS Sierra是必要的，在:code:`stack test`会提示异常），你可以在单独的容器中运行PostgreSQL，也可以使用本地安装的Postgres.app。

使用以下脚本构建测试使用的容器:code:`test/Dockerfile.test`：

.. code:: bash

  $ docker build -t pgst-test - < test/Dockerfile.test
  $ mkdir .stack-work-docker ~/.stack-linux

在测试容器首次运行时，将会花费较长的时间，因为需要缓存相应的依赖资源。创建:code:`~/.stack-linux`文件夹作为容器的挂载卷，以确保我们在一次性模式下运行容器而且不必担心随后的运行会变的迟缓。:code:`.stack-work-docker`同样需要映射至容器中，在使用Linux中的stack时必须指定，以免干扰本地开发的:code:`.stack work`。（在Sierra上:code:`stack build`可以正常使用，而:code:`stack test`在GHC 8.0.1中不会起作用）

文件夹映射至docker容器中：

.. code:: bash

  $ docker run --name pg -e POSTGRES_PASSWORD=pwd  -d postgres
  $ docker run --rm -it -v `pwd`:`pwd` -v ~/.stack-linux:/root/.stack --link pg:pg -w="`pwd`" -v `pwd`/.stack-work-docker:`pwd`/.stack-work pgst-test bash -c "POSTGREST_TEST_CONNECTION=$(test/create_test_db "postgres://postgres:pwd@pg" test_db) stack test"

在mac上，Docker的堆栈测试方式如下：

.. code:: bash

  $ host_ip=$(ifconfig en0 | grep 'inet ' | cut -f 2 -d' ')
  $ export POSTGREST_TEST_CONNECTION=$(test/create_test_db "postgres://postgres@$HOST" test_db)
  $ docker run --rm -it -v `pwd`:`pwd` -v ~/.stack-linux:/root/.stack -v `pwd`/.stack-work-docker:`pwd`/.stack-work -e "HOST=$host_ip" -e "POSTGREST_TEST_CONNECTION=$POSTGREST_TEST_CONNECTION" -w="`pwd`" pgst-test bash -c "stack test"
  $ test/destroy_test_db "postgres://postgres@localhost" test_db
