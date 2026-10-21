#!/usr/bin/env bash
#
# php-8.2.35-hotfix.sh — срочная замена PHP 8.2.34 на 8.2.35 на BitrixVM 9
# Автор: Andrew Berlin — https://github.com/the-berlin
# CVE-2026-109618, CVE-2026-109619: удалённое выполнение кода без авторизации, CVSS v4 9.2.
#
# Собирает PHP 8.2.35 из исходников php.net с параметрами пакетной сборки Remi (php:remi-8.2, el9)
# и подменяет модуль Apache (mod_php), консольный php, php-cgi и встроенные модули расширений.
# Модули PECL (apcu, memcache, zip и т. п.) не трогает: номер API модулей в 8.2.35 тот же (20220829).
#
#   bash php-8.2.35-hotfix.sh build      сборка → проверка → подмена → перезапуск Apache → проверка
#   bash php-8.2.35-hotfix.sh verify     только проверка
#   bash php-8.2.35-hotfix.sh rollback   вернуть файлы 8.2.34 из копии, снятой перед подменой
#
# Ключи:
#   --yes          не спрашивать про снапшот VM
#   --reconfigure  сконфигурировать и собрать заново с нуля
#   --force        подменять, даже если сборка отличается от текущего PHP по функциям и классам
#
# Повторный запуск безопасен: сделанные шаги пропускаются, начатая сборка продолжается с места.
# Рассчитан на BitrixVM 9.0.10 (CentOS Stream 9, PHP 8.2.34 из Remi, Apache с mod_php).

set -Eeuo pipefail

readonly TARGET=8.2.35
readonly TARBALL=php-$TARGET.tar.xz
readonly TARBALL_URL=https://www.php.net/distributions/$TARBALL
readonly TARBALL_SHA256=5737b98601fe5ab1b8c5db0c82ed3158acb9283ed3081ffe2faffb9ac81455e6
readonly WORK=${WORK:-/root/php-build}
readonly SRC=$WORK/php-$TARGET          # сборка модуля Apache и модулей расширений
readonly SRC_CLI=$WORK/php-$TARGET-cli  # сборка консольного php и php-cgi
readonly STATE=$WORK/state
readonly BACKUP=$STATE/php-files-before-$TARGET.tgz
readonly PREVIEW=$STATE/ext-preview
readonly MITIGATION_INI=/etc/php.d/zz-cve-2026-109619.ini
readonly COMPAT_INI=/etc/php.d/00-php-$TARGET-hotfix-compat.ini
readonly DOCROOT=${DOCROOT:-/home/bitrix/www}
readonly APXS=/usr/bin/apxs

# Общие параметры сборки Remi: сняты с php-devel-8.2.34-1.module_php.8.2.el9.remi (php-config).
# Убраны --enable-embed, --enable-dtrace, --cache-file, --with-system-tzdata (опция патча Remi,
# база часовых поясов берётся встроенная), а также --disable-dependency-tracking и --with-exec-dir:
# configure из php.net 8.2.35 их не знает.
readonly REMI_BASE_OPTS=(
  --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --program-prefix=
  --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin
  --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include
  --libdir=/usr/lib64 --libexecdir=/usr/libexec --localstatedir=/var
  --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info
  --enable-rtld-now --with-libdir=lib64
  --with-config-file-path=/etc --with-config-file-scan-dir=/etc/php.d
  --disable-debug --with-pic --disable-rpath --without-pear
  --without-gdbm --with-openssl --with-system-ciphers --with-external-pcre
  --with-external-libcrypt --with-zlib --with-layout=GNU --with-kerberos --with-libxml
  --with-mhash --without-password-argon2 --disable-phpdbg
)
# Выключение модулей, которые Remi собирает отдельными .so (снято с того же php-devel-8.2.34).
# Консольный php собирается с ним: модули расширений берутся из сборки Apache.
# --without-pdo-sqlite добавлен: configure 8.2.35 проверяет pdo_sqlite раньше pdo, и без явного
# выключения pdo_sqlite включается без PDO — сборка падает на компоновке.
readonly REMI_WITHOUT_SHARED=(
  --without-mysqli --disable-pdo --without-pdo-sqlite --disable-gd --disable-dom --disable-dba --without-unixODBC
  --disable-opcache --without-ffi --disable-xmlreader --disable-xmlwriter --without-sodium
  --without-sqlite3 --disable-phar --disable-fileinfo --without-pspell --without-curl
  --disable-posix --disable-xml --disable-simplexml --disable-exif --without-gettext
  --without-iconv --disable-ftp --without-bz2 --disable-ctype --disable-shmop --disable-sockets
  --disable-tokenizer --disable-sysvmsg --disable-sysvshm --disable-sysvsem
)
readonly BASE_DEVEL=(
  gcc gcc-c++ make pkgconf-pkg-config httpd-devel
  libxml2-devel openssl-devel pcre2-devel zlib-devel libxcrypt-devel krb5-devel
)

# Модуль → параметры configure. Вид опции (enable/with) сверен с config.m4 исходников 8.2.35.
declare -A MOD_OPT=(
  [bcmath]="--enable-bcmath=shared"           [bz2]="--with-bz2=shared"
  [calendar]="--enable-calendar=shared"       [ctype]="--enable-ctype=shared"
  [curl]="--with-curl=shared"                 [dom]="--enable-dom=shared"
  [dba]="--enable-dba=shared --with-db4 --enable-inifile --enable-flatfile"
  [enchant]="--with-enchant=shared"           [exif]="--enable-exif=shared"
  [ffi]="--with-ffi=shared"                   [fileinfo]="--enable-fileinfo=shared"
  [ftp]="--enable-ftp=shared"                 [gd]="--enable-gd=shared"
  [gettext]="--with-gettext=shared"           [gmp]="--with-gmp=shared"
  [iconv]="--with-iconv=shared"               [imap]="--with-imap=shared --with-imap-ssl"
  [intl]="--enable-intl=shared"               [ldap]="--with-ldap=shared --with-ldap-sasl"
  [mbstring]="--enable-mbstring=shared"       [mysqlnd]="--enable-mysqlnd=shared"
  [mysqli]="--with-mysqli=shared,mysqlnd"     [odbc]="--with-unixODBC=shared,/usr"
  [opcache]="--enable-opcache"                [pdo]="--enable-pdo=shared"
  [pdo_dblib]="--with-pdo-dblib=shared,/usr"  [pdo_firebird]="--with-pdo-firebird=shared"
  [pdo_mysql]="--with-pdo-mysql=shared,mysqlnd"
  [pdo_odbc]="--with-pdo-odbc=shared,unixODBC,/usr"
  [pdo_pgsql]="--with-pdo-pgsql=shared"       [pdo_sqlite]="--with-pdo-sqlite=shared"
  [pgsql]="--with-pgsql=shared"               [phar]="--enable-phar=shared"
  [posix]="--enable-posix=shared"             [pspell]="--with-pspell=shared"
  [readline]="--with-libedit=shared"          [shmop]="--enable-shmop=shared"
  [simplexml]="--enable-simplexml=shared"     [snmp]="--with-snmp=shared"
  [soap]="--enable-soap=shared"               [sockets]="--enable-sockets=shared"
  [sodium]="--with-sodium=shared"             [sqlite3]="--with-sqlite3=shared"
  [sysvmsg]="--enable-sysvmsg=shared"         [sysvsem]="--enable-sysvsem=shared"
  [sysvshm]="--enable-sysvshm=shared"         [tidy]="--with-tidy=shared"
  [tokenizer]="--enable-tokenizer=shared"     [xml]="--enable-xml=shared"
  [xmlreader]="--enable-xmlreader=shared"     [xmlwriter]="--enable-xmlwriter=shared"
  [xsl]="--with-xsl=shared"
)
# Модули, которые в PHP включены по умолчанию: если их нет на сервере, их надо выключить явно.
declare -A MOD_OFF=(
  [ctype]=--disable-ctype         [dom]=--disable-dom             [fileinfo]=--disable-fileinfo
  [iconv]=--without-iconv         [opcache]=--disable-opcache     [pdo]=--disable-pdo
  [pdo_sqlite]=--without-pdo-sqlite [phar]=--disable-phar         [posix]=--disable-posix
  [simplexml]=--disable-simplexml [sqlite3]=--without-sqlite3     [tokenizer]=--disable-tokenizer
  [xml]=--disable-xml             [xmlreader]=--disable-xmlreader [xmlwriter]=--disable-xmlwriter
)
declare -A MOD_DEVEL=(
  [bz2]=bzip2-devel [curl]=libcurl-devel [dba]="libdb-devel" [enchant]=enchant2-devel
  [ffi]=libffi-devel [gmp]=gmp-devel [imap]="libc-client-devel uw-imap-devel"
  [gd]="libpng-devel libjpeg-turbo-devel libwebp-devel freetype-devel libXpm-devel libavif-devel"
  [intl]=libicu-devel [ldap]="openldap-devel cyrus-sasl-devel" [mbstring]=oniguruma-devel
  [odbc]=unixODBC-devel [pdo_dblib]=freetds-devel [pdo_firebird]=firebird-devel
  [pdo_odbc]=unixODBC-devel [pdo_pgsql]=libpq-devel [pdo_sqlite]=sqlite-devel [pgsql]=libpq-devel
  [pspell]=aspell-devel [readline]=libedit-devel [snmp]=net-snmp-devel [sodium]=libsodium-devel
  [sqlite3]=sqlite-devel [tidy]=libtidy-devel [xsl]=libxslt-devel
)

MODE=
ASSUME_YES=0
RECONFIGURE=0
FORCE=0

say()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }
die()  { printf '\nОШИБКА: %s\n' "$*" >&2; exit 1; }
trap 'warn "строка $LINENO: команда завершилась с ошибкой: $BASH_COMMAND"' ERR

usage() {
  cat >&2 <<'EOF'
Использование: bash php-8.2.35-hotfix.sh build|verify|rollback [--yes] [--reconfigure] [--force]
  build     собрать PHP 8.2.35, проверить, подменить, перезапустить Apache и проверить ещё раз
  verify    только проверка
  rollback  вернуть файлы 8.2.34 из копии, снятой перед подменой
EOF
  exit 2
}

parse_args() {
  (( $# )) || usage
  MODE=$1; shift
  case $MODE in build|verify|rollback) ;; *) usage ;; esac
  local a
  for a in "$@"; do
    case $a in
      --yes|-y) ASSUME_YES=1 ;;
      --reconfigure) RECONFIGURE=1 ;;
      --force) FORCE=1 ;;
      *) usage ;;
    esac
  done
}

# ---------------------------------------------------------------- окружение

preflight() {
  [[ $EUID -eq 0 ]] || die "запускать от root"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ ${PLATFORM_ID:-} == platform:el9 ]] || die "ожидается EL9, а здесь ${PRETTY_NAME:-неизвестная система}"
  command -v php >/dev/null || die "не найден php"
  command -v httpd >/dev/null || die "не найден httpd"
  httpd -M 2>/dev/null | grep 'php_module' >/dev/null || die "Apache не загружает mod_php — скрипт рассчитан на mod_php"

  CUR=$(php -r 'echo PHP_VERSION;')
  [[ $CUR == 8.2.* ]] || die "PHP $CUR — скрипт только для ветки 8.2"
  EXT_DIR=$(php -r 'echo PHP_EXTENSION_DIR;')
  LIBPHP=$(rpm -ql php 2>/dev/null | grep -E '/libphp\.so$' | head -n1 || true)
  LIBPHP=${LIBPHP:-/usr/lib64/httpd/modules/libphp.so}
  [[ -f $LIBPHP ]] || die "не найден модуль Apache $LIBPHP"

  if systemctl is-active --quiet php-fpm 2>/dev/null; then
    die "php-fpm запущен: скрипт подменяет только mod_php и CLI, а php-fpm остался бы на $CUR"
  fi

  local vendor bxenv
  vendor=$(rpm -q --qf '%{VENDOR}' php-common 2>/dev/null || true)
  bxenv=$(rpm -qa 'bitrix-env*' 2>/dev/null | head -n1 || true)
  info "система:      ${PRETTY_NAME:-?}"
  info "окружение:    ${bxenv:-bitrix-env не найден}"
  info "PHP сейчас:   $CUR (php-common от: ${vendor:-неизвестно})"
  info "модули:       $EXT_DIR"
  info "mod_php:      $LIBPHP"
  [[ $vendor == *Remi* ]] || warn "php-common не из репозитория Remi — параметры сборки могут не совпасть"
  if [[ -x /usr/sbin/php-fpm || -x /usr/bin/phpdbg ]] || compgen -G '/usr/lib64/libphp*.so' >/dev/null; then
    warn "php-fpm, phpdbg или встроенная библиотека libphp установлены, но не запущены — они останутся $CUR"
  fi
}

take_lock() {
  exec 9>/run/php-$TARGET-hotfix.lock
  flock -n 9 || die "скрипт уже запущен в другом окне"
}

confirm_snapshot() {
  [[ $ASSUME_YES == 1 || -f $STATE/snapshot-confirmed ]] && return 0
  local answer
  read -r -p "Снапшот VM в гипервизоре сделан? Введите yes: " answer
  [[ $answer == yes ]] || die "сначала снапшот VM"
  touch "$STATE/snapshot-confirmed"
}

# Не мешать уже идущей вручную сборке в том же каталоге.
guard_src_busy() {
  local p cwd comm
  for p in /proc/[0-9]*; do
    comm=$(cat "$p/comm" 2>/dev/null) || continue
    case $comm in make|gmake|configure|cc1|cc1plus|gcc|g++|cc|ld|as|libtool) ;; *) continue ;; esac
    cwd=$(readlink "$p/cwd" 2>/dev/null) || continue
    if [[ $cwd == "$SRC" || $cwd == "$SRC"/* || $cwd == "$SRC_CLI" || $cwd == "$SRC_CLI"/* ]]; then
      die "в $cwd уже идёт $comm (PID ${p#/proc/}) — дождитесь окончания и запустите скрипт снова"
    fi
  done
}

# ---------------------------------------------------------------- снимок поведения PHP

write_probe() {
  cat > "$STATE/probe.php" <<'PHP'
<?php
// Снимок поведения PHP: расширения и их функции, классы, значения ini, возможности gd.
$o = ['version' => PHP_VERSION, 'ext' => []];
foreach (get_loaded_extensions() as $e) {
    $f = get_extension_funcs($e) ?: [];
    sort($f);
    $o['ext'][strtolower($e)] = $f;
}
ksort($o['ext']);
$c = get_declared_classes();
sort($c);
$o['classes'] = $c;
$i = ini_get_all(null, false);
unset($i['extension_dir'], $i['session.upload_progress.enabled']);
ksort($i);
$o['ini'] = $i;
if (function_exists('gd_info')) {
    $g = gd_info();
    unset($g['GD Version']);
    $o['gd'] = $g;
}
echo json_encode($o, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR), "\n";
PHP
  cat > "$STATE/inidiff.php" <<'PHP'
<?php
// Значения ini, которые у новой сборки по умолчанию другие: возвращает строки для php.d.
$a = json_decode(file_get_contents($argv[1]), true)['ini'] ?? [];
$b = json_decode(file_get_contents($argv[2]), true)['ini'] ?? [];
foreach ($a as $k => $v) {
    if ($v !== null && array_key_exists($k, $b) && $b[$k] !== $v) {
        printf("%s = \"%s\"\n", $k, addcslashes((string) $v, "\"\\"));
    }
}
PHP
}

# Снимок без строки версии: версия в сравнении всегда разная.
probe_cli() { # $1 — php, остальное — его ключи
  local bin=$1; shift
  "$bin" "$@" "$STATE/probe.php" 2>&1 | sed '/"version":/d'
}

apache_url() {
  local hp
  hp=$(ss -ltnpH 2>/dev/null | awk '/"httpd"/ {print $4}' | sort -u | grep -m1 -E '^127\.0\.0\.1:' || true)
  [[ -n $hp ]] || hp=$(ss -ltnpH 2>/dev/null | awk '/"httpd"/ {print $4}' | head -n1 || true)
  [[ -n $hp ]] || return 1
  hp=${hp/#\*:/127.0.0.1:}
  hp=${hp/#0.0.0.0:/127.0.0.1:}
  hp=${hp/#\[::\]:/127.0.0.1:}
  printf 'http://%s' "$hp"
}

probe_web() { # снимок через Apache; пустой вывод — снять не удалось
  local base name out
  base=$(apache_url) || return 0
  [[ -d $DOCROOT ]] || return 0
  name=php-hotfix-probe-$$-$RANDOM.php
  install -m 644 "$STATE/probe.php" "$DOCROOT/$name"
  out=$(curl -s --max-time 20 "$base/$name" || true)
  rm -f "$DOCROOT/$name"
  [[ $out == *'"ext":'* ]] && printf '%s\n' "$out"
  return 0
}

web_version() {
  local j
  j=$(probe_web)
  [[ -n $j ]] || { echo "?"; return; }
  sed -n '/"version":/{s/^ *"version": *"\([^"]*\)".*/\1/p;q}' <<<"$j"
}

take_baseline() {
  if [[ -s $STATE/baseline-cli.json ]]; then
    info "снимок PHP $CUR уже есть"
    return
  fi
  if [[ $CUR == "$TARGET" ]]; then
    warn "PHP уже $TARGET, а снимка прежней версии нет — сравнивать будет не с чем"
    return
  fi
  probe_cli php > "$STATE/baseline-cli.json"
  probe_web | sed '/"version":/d' > "$STATE/baseline-web.json"
  php -m > "$STATE/baseline-modules.txt"
  [[ -s $STATE/baseline-web.json ]] || warn "снимок через Apache снять не удалось ($(apache_url || echo 'нет адреса'), $DOCROOT)"
  info "снимок PHP $CUR сохранён: функции, классы и ini каждого модуля"
}

# ---------------------------------------------------------------- шаги сборки

apply_mitigation() {
  local want='session.upload_progress.enabled = 0'
  if [[ -f $MITIGATION_INI ]] && grep -qxF "$want" "$MITIGATION_INI"; then
    info "временная мера против CVE-2026-109619 уже стоит"
    return
  fi
  printf '; Временная мера против CVE-2026-109619 на время сборки PHP %s\n%s\n' "$TARGET" "$want" > "$MITIGATION_INI"
  httpd -t
  systemctl restart httpd
  info "session.upload_progress выключен, Apache перезапущен"
}

fetch_source() {
  say "Исходники PHP $TARGET"
  mkdir -p "$WORK"
  if [[ -f $WORK/$TARBALL ]] && (cd "$WORK" && echo "$TARBALL_SHA256  $TARBALL" | sha256sum -c --quiet - >/dev/null 2>&1); then
    info "архив уже скачан, контрольная сумма сходится"
  else
    curl -fsSL --retry 3 -o "$WORK/$TARBALL.part" "$TARBALL_URL"
    mv -f "$WORK/$TARBALL.part" "$WORK/$TARBALL"
    (cd "$WORK" && echo "$TARBALL_SHA256  $TARBALL" | sha256sum -c -) || die "контрольная сумма архива не сходится"
  fi
  if [[ -f $SRC/configure && -f $SRC/main/php_version.h ]]; then
    info "исходники для сборки Apache уже распакованы"
  else
    tar -xf "$WORK/$TARBALL" -C "$WORK"
  fi
  if [[ -f $SRC_CLI/configure && -f $SRC_CLI/main/php_version.h ]]; then
    info "исходники для консольной сборки уже распакованы"
  else
    mkdir -p "$SRC_CLI"
    tar -xf "$WORK/$TARBALL" -C "$SRC_CLI" --strip-components=1
  fi
}

# Встроенные модули PHP на сервере: файлы в каталоге модулей, принадлежащие пакетам из исходника php-8.2.x.
collect_modules() {
  BUILD_MODS=() SKIP_MODS=()
  local so mod owner
  declare -gA PRESENT=()
  for so in "$EXT_DIR"/*.so; do
    [[ -e $so ]] || continue
    owner=$(rpm -qf --qf '%{SOURCERPM}' "$so" 2>/dev/null || true)
    [[ $owner == php-8.2.* ]] || continue
    mod=${so##*/}; mod=${mod%.so}
    PRESENT[$mod]=1
    if [[ -n ${MOD_OPT[$mod]:-} ]]; then BUILD_MODS+=("$mod"); else SKIP_MODS+=("$mod"); fi
  done
  (( ${#BUILD_MODS[@]} )) || die "в $EXT_DIR не нашёл модулей из пакетов PHP"
  info "соберу модули (${#BUILD_MODS[@]}): ${BUILD_MODS[*]}"
  (( ${#SKIP_MODS[@]} == 0 )) || warn "не умею собирать и оставляю $CUR: ${SKIP_MODS[*]}"

  # Модули, вкомпилированные в консольный php (у Remi так собраны pcntl и readline).
  CLI_STATIC=() CLI_DEVEL=()
  if [[ -s $STATE/baseline-modules.txt ]]; then
    if grep -qx pcntl "$STATE/baseline-modules.txt" && [[ -z ${PRESENT[pcntl]:-} ]]; then
      CLI_STATIC+=(--enable-pcntl)
    fi
    if grep -qx readline "$STATE/baseline-modules.txt" && [[ -z ${PRESENT[readline]:-} ]]; then
      if ldd /usr/bin/php 2>/dev/null | grep 'libreadline' >/dev/null; then
        CLI_STATIC+=(--with-readline); CLI_DEVEL+=(readline-devel)
      else
        CLI_STATIC+=(--with-libedit); CLI_DEVEL+=(libedit-devel)
      fi
    fi
  fi
  (( ${#CLI_STATIC[@]} == 0 )) || info "в консольный php вкомпилирую: ${CLI_STATIC[*]}"
}

install_build_deps() {
  say "Пакеты для сборки"
  local -a pkgs=("${BASE_DEVEL[@]}" "${CLI_DEVEL[@]}")
  local mod
  for mod in "${BUILD_MODS[@]}"; do
    # shellcheck disable=SC2206
    [[ -z ${MOD_DEVEL[$mod]:-} ]] || pkgs+=(${MOD_DEVEL[$mod]})
  done
  # Метаданные Remi сейчас частично синхронизированы, поэтому репозитории Remi выключены:
  # всё нужное для сборки лежит в BaseOS, AppStream, CRB и EPEL.
  dnf install -y --disablerepo='remi*' --setopt=strict=0 --setopt=skip_if_unavailable=True "${pkgs[@]}"
  command -v gcc >/dev/null && command -v make >/dev/null || die "gcc или make не установились"
  [[ -x $APXS ]] || die "не установился httpd-devel ($APXS)"
}

configure_args() {
  CONF_ARGS=("${REMI_BASE_OPTS[@]}" "--with-apxs2=$APXS")
  local mod
  for mod in $(printf '%s\n' "${!MOD_OFF[@]}" | sort); do
    [[ -n ${PRESENT[$mod]:-} ]] || CONF_ARGS+=("${MOD_OFF[$mod]}")
  done
  for mod in "${BUILD_MODS[@]}"; do
    # shellcheck disable=SC2206
    CONF_ARGS+=(${MOD_OPT[$mod]})
  done
  if [[ -n ${PRESENT[gd]:-} ]]; then
    pkg-config --exists libjpeg && CONF_ARGS+=(--with-jpeg)
    pkg-config --exists libwebp && CONF_ARGS+=(--with-webp)
    pkg-config --exists freetype2 && CONF_ARGS+=(--with-freetype)
    pkg-config --exists xpm && CONF_ARGS+=(--with-xpm)
    pkg-config --exists libavif && CONF_ARGS+=(--with-avif)
  fi
  if [[ -n ${PRESENT[mysqlnd]:-} ]]; then
    # Путь к сокету MySQL по умолчанию — тот же, что действует сейчас.
    local sock
    sock=$(php -r 'echo ini_get("mysqli.default_socket") ?: ini_get("pdo_mysql.default_socket");')
    [[ -z $sock ]] || CONF_ARGS+=("--with-mysql-sock=$sock")
  fi
  CONF_ENV=(
    "EXTENSION_DIR=$EXT_DIR"
    "CFLAGS=-O2 -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fcf-protection -fasynchronous-unwind-tables"
    "CXXFLAGS=-O2 -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fcf-protection -fasynchronous-unwind-tables"
    "LDFLAGS=-Wl,-z,relro -Wl,-z,now -Wl,--as-needed"
  )
}

# Как у Remi, сборок две. В сборке вместе с модулем Apache PHP не включает то, что доступно
# только консоли: функцию chroot() и модули pcntl и readline. Поэтому консольный php и php-cgi
# собираются отдельно, без модуля Apache; модули расширений берутся из сборки Apache.
configure_source() {
  say "Конфигурация сборки"
  configure_args
  if [[ -f $STATE/configure.args && ! -f $STATE/configure-apache.args ]]; then
    mv -f "$STATE/configure.args" "$STATE/configure-apache.args"
  fi
  configure_dir "$SRC" apache "${CONF_ARGS[@]}"
  configure_dir "$SRC_CLI" cli "${REMI_BASE_OPTS[@]}" "${REMI_WITHOUT_SHARED[@]}" "${CLI_STATIC[@]}"
}

configure_dir() { # $1 — каталог исходников, $2 — имя сборки, дальше — параметры configure
  local dir=$1 name=$2
  shift 2
  local stamp=$STATE/configure-$name.args log=$STATE/configure-$name.log
  printf '%s\n' "${CONF_ENV[@]}" "$@" > "$stamp.want"
  if [[ $RECONFIGURE == 0 && -x $dir/config.status && -f $stamp ]] && cmp -s "$stamp" "$stamp.want"; then
    info "$name: уже сконфигурировано с теми же параметрами"
    return
  fi
  cd "$dir"
  if [[ -f Makefile ]]; then make distclean >/dev/null 2>&1 || true; fi
  rm -f "$stamp"
  info "$name: configure, лог $log"
  if ! env "${CONF_ENV[@]}" ./configure "$@" > "$log" 2>&1; then
    tail -n 20 "$log" >&2
    die "configure ($name) остановился. Поставьте недостающий пакет (dnf install --disablerepo='remi*' <имя>-devel) и запустите скрипт снова"
  fi
  grep -qE "^#define PHP_EXTENSION_DIR[[:space:]]+\"$EXT_DIR\"" main/build-defs.h \
    || die "сборка $name ищет модули не в $EXT_DIR"
  mv -f "$stamp.want" "$stamp"
  cd /
}

compile() {
  say "Сборка"
  make_dir "$SRC" apache
  make_dir "$SRC_CLI" cli
  [[ -s $SRC/libs/libphp.so ]] || die "после сборки нет модуля Apache libs/libphp.so"
  [[ -s $SRC_CLI/sapi/cli/php ]] || die "после сборки нет консольного sapi/cli/php"
  local mod
  for mod in "${BUILD_MODS[@]}"; do
    [[ -s $SRC/modules/$mod.so ]] || die "после сборки нет модуля $mod.so"
  done
  info "собрано"
}

make_dir() { # $1 — каталог исходников, $2 — имя сборки
  local dir=$1 name=$2 log=$STATE/make-$2.log
  info "$name: идёт make, ход можно смотреть: tail -f $log"
  cd "$dir"
  if ! nice -n 10 make -j"$(nproc)" > "$log" 2>&1; then
    tail -n 30 "$log" >&2
    die "make ($name) упал, полный лог: $log"
  fi
  cd /
}

# Снимок новой сборки так, как он будет после подмены: прежние модули PECL + новые встроенные.
check_build() {
  say "Проверка сборки до подмены"
  local v e mod
  v=$("$SRC_CLI/sapi/cli/php" -n -r 'echo PHP_VERSION;')
  [[ $v == "$TARGET" ]] || die "собранный php сообщает версию $v"
  e=$("$SRC_CLI/sapi/cli/php" -n -r 'echo PHP_EXTENSION_DIR;')
  [[ $e == "$EXT_DIR" ]] || die "собранный php ищет модули в $e, а нужно $EXT_DIR"

  rm -rf "$PREVIEW"
  mkdir -p "$PREVIEW"
  for e in "$EXT_DIR"/*.so; do ln -s "$e" "$PREVIEW/${e##*/}"; done
  for mod in "${BUILD_MODS[@]}"; do ln -sfn "$SRC/modules/$mod.so" "$PREVIEW/$mod.so"; done

  compare_cli "$SRC_CLI/sapi/cli/php" -d "extension_dir=$PREVIEW"
  info "версия $TARGET, каталог модулей $EXT_DIR, функции, классы и ini совпадают с $CUR"
}

# Сравнить снимок php с сохранённым. Разницу в ini по умолчанию закрывает файлом совместимости.
compare_cli() {
  [[ -s $STATE/baseline-cli.json ]] || { warn "нет снимка прежней версии — сравнение пропущено"; return; }
  probe_cli "$@" > "$STATE/new-cli.json"
  if cmp -s "$STATE/baseline-cli.json" "$STATE/new-cli.json"; then return; fi

  local compat
  compat=$(php -n "$STATE/inidiff.php" "$STATE/baseline-cli.json" "$STATE/new-cli.json" || true)
  if [[ -n $compat ]]; then
    {
      printf '; Значения, которые у PHP %s из пакета Remi были встроены по умолчанию.\n' "$CUR"
      printf '; Создано php-%s-hotfix.sh, чтобы поведение не изменилось. Удалится при откате.\n' "$TARGET"
      printf '%s\n' "$compat"
    } > "$COMPAT_INI"
    warn "у новой сборки другие значения ini по умолчанию — прежние закреплены в $COMPAT_INI:"
    sed 's/^/      /' <<<"$compat" >&2
    probe_cli "$@" > "$STATE/new-cli.json"
    cmp -s "$STATE/baseline-cli.json" "$STATE/new-cli.json" && return
  fi

  diff -u "$STATE/baseline-cli.json" "$STATE/new-cli.json" > "$STATE/diff-cli.txt" || true
  warn "новая сборка отличается от $CUR (полностью — $STATE/diff-cli.txt):"
  tail -n +3 "$STATE/diff-cli.txt" | head -n 150 >&2 || true
  [[ $FORCE == 1 ]] && { warn "--force: продолжаю несмотря на разницу"; return; }
  die "подмена остановлена. Разберите разницу выше; продолжить всё равно — ключ --force"
}

backup_once() {
  if [[ -s $BACKUP ]]; then
    info "копия файлов $(cat "$STATE/backup.version" 2>/dev/null || echo 'прежней версии') уже есть: $BACKUP"
    return
  fi
  [[ $CUR != "$TARGET" ]] || die "PHP уже $TARGET, а копии прежних файлов нет — откат только снапшотом"
  local -a rel=()
  local f
  for f in "${SWAP_DST[@]}"; do rel+=("${f#/}"); done
  tar -czf "$BACKUP.part" -C / "${rel[@]}"
  mv -f "$BACKUP.part" "$BACKUP"
  echo "$CUR" > "$STATE/backup.version"
  info "копия файлов $CUR: $BACKUP"
}

plan_swaps() {
  SWAP_SRC=("$SRC/libs/libphp.so" "$SRC_CLI/sapi/cli/php")
  SWAP_DST=("$LIBPHP" /usr/bin/php)
  if [[ -x /usr/bin/php-cgi && -s $SRC_CLI/sapi/cgi/php-cgi ]]; then
    SWAP_SRC+=("$SRC_CLI/sapi/cgi/php-cgi"); SWAP_DST+=(/usr/bin/php-cgi)
  elif [[ -x /usr/bin/php-cgi ]]; then
    warn "php-cgi не собрался — /usr/bin/php-cgi останется $CUR (Apache его не использует)"
  fi
  local mod
  for mod in "${BUILD_MODS[@]}"; do
    SWAP_SRC+=("$SRC/modules/$mod.so"); SWAP_DST+=("$EXT_DIR/$mod.so")
  done
}

swap_files() {
  say "Подмена файлов"
  CHANGED=0
  local i src dst
  for i in "${!SWAP_SRC[@]}"; do
    src=${SWAP_SRC[$i]} dst=${SWAP_DST[$i]}
    cmp -s "$src" "$dst" && continue
    # Через переименование: работающий Apache держит старый файл до перезапуска и не падает.
    install -m 755 "$src" "$dst.hotfix-new"
    mv -f "$dst.hotfix-new" "$dst"
    CHANGED=$((CHANGED + 1))
  done
  if command -v selinuxenabled >/dev/null && selinuxenabled; then restorecon "${SWAP_DST[@]}"; fi
  info "заменено файлов: $CHANGED из ${#SWAP_DST[@]}"
}

restore_backup() {
  [[ -s $BACKUP ]] || die "нет копии $BACKUP — откат только снапшотом VM"
  tar -xzf "$BACKUP" -C /
  rm -f "$COMPAT_INI"
  if command -v selinuxenabled >/dev/null && selinuxenabled; then restorecon -R "$EXT_DIR" "$LIBPHP" /usr/bin/php*; fi
}

restart_apache() {
  if (( CHANGED == 0 )) && [[ $(web_version) == "$TARGET" ]]; then
    info "Apache уже работает на $TARGET — перезапуск не нужен"
    return
  fi
  if ! httpd -t; then
    warn "конфигурация Apache не проходит проверку — возвращаю прежние файлы"
    restore_backup
    die "откат выполнен, Apache не перезапускался"
  fi
  systemctl restart httpd
  if ! systemctl is-active --quiet httpd; then
    warn "Apache не поднялся — возвращаю прежние файлы"
    restore_backup
    systemctl restart httpd
    die "откат выполнен; причина: journalctl -u httpd -n 50"
  fi
  info "Apache перезапущен"
}

# ---------------------------------------------------------------- режимы

verify() {
  say "Проверка"
  local ok=1 cli web
  cli=$(php -r 'echo PHP_VERSION;')
  web=$(web_version)
  info "консоль: $cli"
  info "Apache:  $web"
  [[ $cli == "$TARGET" ]] || { warn "консольный php не $TARGET"; ok=0; }
  if [[ $web == "?" ]]; then
    warn "версию через Apache снять не удалось ($(apache_url || echo 'не найден порт httpd'), $DOCROOT) — проверьте вручную"
    ok=0
  elif [[ $web != "$TARGET" ]]; then
    warn "Apache отдаёт $web — перезапустите httpd"
    ok=0
  fi

  if [[ -s $STATE/baseline-cli.json ]]; then
    probe_cli php > "$STATE/after-cli.json"
    if cmp -s "$STATE/baseline-cli.json" "$STATE/after-cli.json"; then
      info "консоль: функции, классы и ini те же, что у прежней версии"
    else
      warn "консоль отличается от прежней версии:"
      diff -u "$STATE/baseline-cli.json" "$STATE/after-cli.json" | tail -n +3 | head -n 40 >&2 || true
      ok=0
    fi
  fi
  if [[ -s $STATE/baseline-web.json ]]; then
    probe_web | sed '/"version":/d' > "$STATE/after-web.json"
    if cmp -s "$STATE/baseline-web.json" "$STATE/after-web.json"; then
      info "Apache: функции, классы и ini те же, что у прежней версии"
    else
      warn "Apache отличается от прежней версии:"
      diff -u "$STATE/baseline-web.json" "$STATE/after-web.json" | tail -n +3 | head -n 40 >&2 || true
      ok=0
    fi
  fi

  info "последние строки журнала Apache:"
  tail -n 10 /var/log/httpd/error_log 2>/dev/null | sed 's/^/      /' || true
  if [[ -f $MITIGATION_INI ]]; then
    info "временная мера $MITIGATION_INI оставлена; после проверки портала её можно удалить и перезапустить httpd"
  fi
  (( ok )) || die "проверка не пройдена — см. выше"
  say "ГОТОВО: PHP $TARGET в консоли и в Apache, поведение совпадает с прежним"
}

mode_build() {
  confirm_snapshot
  guard_src_busy
  if [[ $CUR != "$TARGET" ]]; then apply_mitigation; fi
  take_baseline
  fetch_source
  collect_modules
  install_build_deps
  configure_source
  compile
  check_build
  plan_swaps
  backup_once
  swap_files
  restart_apache
  verify
}

mode_rollback() {
  say "Откат"
  CHANGED=1
  restore_backup
  httpd -t
  systemctl restart httpd
  info "возвращены файлы $(cat "$STATE/backup.version" 2>/dev/null || echo 'из копии'); консоль: $(php -r 'echo PHP_VERSION;'), Apache: $(web_version)"
  info "временная мера $MITIGATION_INI оставлена: PHP снова уязвим"
}

main() {
  parse_args "$@"
  cd /
  mkdir -p "$STATE"
  exec > >(tee -a "$STATE/hotfix.log") 2>&1
  printf '\n######## %s  %s %s\n' "$(date -u +%FT%TZ)" "$0" "$*"
  take_lock
  trap 'rm -f "$DOCROOT"/php-hotfix-probe-$$-*.php' EXIT
  say "Окружение"
  preflight
  write_probe
  case $MODE in
    build) mode_build ;;
    verify) verify ;;
    rollback) mode_rollback ;;
  esac
}

main "$@"
