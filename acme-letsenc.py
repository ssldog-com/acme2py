import hashlib
import hmac
import re
import time
import binascii
import base64
import logging
import os
import sys

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID

# 忽略 warnings.warn
requests.packages.urllib3.disable_warnings()

# 日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(funcName)-24s]# %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

DEFAULT_CA = 'letsencrypt'
DEFAULT_TYPE = 'dns'
DEFAULT_ACCOUNT_KEY_LENGTH = 'ec-256'
DEFAULT_DOMAIN_KEY_LENGTH = 'ec-256'
ECC_NAME = 'prime256v1'
ECC_KEY_LEN = '256'

# TODO add RSA2048
DOMAIN_KEY_RSA = False
DOMAIN_KEY_RSA_LEN = '2048'

CA_LETSENCRYPT_V2 = "https://acme-v02.api.letsencrypt.org/directory"
CA_LETSENCRYPT_V2_TEST = "https://acme-staging-v02.api.letsencrypt.org/directory"
# CA_LETSENCRYPT_V2 = "https://acme-staging-v02.api.letsencrypt.org/directory"
CA_DIR = "./ca/acme-v02.api.letsencrypt.org/directory"

# 创建ca目录
if not os.path.exists(CA_DIR):
    os.makedirs(CA_DIR)

# account.key
ACCOUNT_KEY = os.path.abspath(CA_DIR+'/'+'account.key')

# account.json
ACCOUNT_JSON = os.path.abspath(CA_DIR+'/'+'account.json')

# ca.conf
CA_EMAIL = 'thankyou@' + os.urandom(8).hex() + '.com'  # 如果不输入 email=youremail，则随机生成
CA_CONF = os.path.abspath(CA_DIR+'/'+'ca.conf')
ACCOUNT_URL = ''  # 在申请证书时要用
CA_EAB_KEY_ID = ''
CA_EAB_HMAC_KEY = ''

# 输入 domain=MAIN_DOMAIN
MAIN_DOMAIN = ''  # 输入的第一个域名
ALT_DOMAINS = ''  # 输入的其他域名

# 域名证书申请相关文件
CERT_KEY_PATH = ''  # ./domain/domain.key
CSR_PATH = ''  # ./domain/domain.csr
CSR_CONF_PATH = ''  # ./domain/domain.csr.conf#acme.sh -> DOMAIN_SSL_CONF
DOMAIN_CONF_PATH = ''  # ./domain/domain.conf"
CA_CERT_PATH = ''  # ./domain/ca.cer
DOMAIN_CER_PATH = ''  # ./domain/domain.cer#acme.sh -> CERT_PATH
FULLCHAIN_CER_PATH = ''  # ./domain/fullchain.cer#acme.sh -> CERT_FULLCHAIN_PATH

# letsencrypt
NEW_ACCOUNT =  "https://acme-v02.api.letsencrypt.org/acme/new-acct"
NEW_NONCE = "https://acme-v02.api.letsencrypt.org/acme/new-nonce"
NEW_ORDER = "https://acme-v02.api.letsencrypt.org/acme/new-order"
# renewalInfo = "https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo"
REVOKE_CERT = "https://acme-v02.api.letsencrypt.org/acme/revoke-cert"


# jwk信息不变
JWK = ''
# JWK_HEADER = String.format("\"{\"alg\": \"ES%s\", \"jwk\": %s}\"",ECC_KEY_LEN,jwk)

# 域名验证时共享
SHARED_NONCE = ''

# 域名txt记录
challs_for_domain = {}
txt_for_domain = {}
authrs_for_domain = {}

# thumbprint 信息不变
thumbprint = ''


###################################################################################

def new_nonce():
    global SHARED_NONCE
    if SHARED_NONCE:
        return SHARED_NONCE

    headers = {
        'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
        'accept': '*/*',
        'content-type': 'application/jose+json'}
    payload = None
    response = requests.request("HEAD", NEW_NONCE, headers=headers, data=payload, verify=False)

    SHARED_NONCE = response.headers['replay-nonce'] # Replay-Nonce

    logger.info(f'new_nonce: {SHARED_NONCE}')

    logger.info(f'http_header: {response.headers}')
    return SHARED_NONCE


def sign(data, private_key_path):
    logger.info(f'数据签名: {data}')
    # echo -n "$data" | openssl dgst -sign account.key -sha256 | openssl asn1parse -inform DER

    # 从PEM文件加载ECC私钥
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # 使用私钥和SHA256对数据进行签名
    signature = private_key.sign(
        data.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    # 将签名转换为ASN.1 DER编码
    # 在cryptography中，签名结果已经是DER编码，无需额外转换
    # 但是，为了与OpenSSL的asn1parse命令输出相匹配，我们可以解析DER编码的签名结构
    der_signature_r, der_signature_s = utils.decode_dss_signature(signature)
    der_signature_hex = binascii.hexlify(
        der_signature_r.to_bytes(32, byteorder='big') + der_signature_s.to_bytes(32, byteorder='big'))

    logger.info(f'签名结果: {der_signature_hex}')

    return der_signature_hex


def sign_base64_url_replace(data, private_key_path):
    signature = sign(data, private_key_path)
    s64 = base64.urlsafe_b64encode(bytes.fromhex(signature.decode('ascii'))).decode('ascii').replace('=', '')
    logger.info(f'签名结果: {s64}')
    return s64


def read_config(key, conf_path):
    """
    从指定配置文件中读取给定键对应的值。

    :param key: 要查找的键
    :param conf_path: 配置文件的路径
    :return: 键对应的值，如果未找到则返回None
    """

    logger.info(f'读取配置文件 {conf_path} 中的 {key}')
    try:
        with open(conf_path, 'r') as file:
            for line in file:
                # 去除行尾的换行符并分割字符串
                parts = line.strip().split('=')
                if len(parts) == 2 and parts[0].strip() == key:
                    # 假设等号右侧的值被单引号或双引号包围，去除引号
                    value = parts[1].strip("'\"")
                    return value
                    # 如果遍历完文件都没有找到键，则返回None
        return None
    except FileNotFoundError:
        logger.error(f"!!! 文件 {conf_path} 未找到。")
        return None
    except Exception as e:
        logger.error(f"!!! 读取配置文件时发生错误: {e}")
        return None


def calc_thumbprint(jwk):
    """
    acme.sh: openssl -> echo -n '$JWK' | tr -d ' ' | openssl dgst -sha256 -binary | openssl base64 -e -A
    :param jwk:
    :return:
    """
    # 方法同account_key_hash
    global thumbprint

    if thumbprint:
        return thumbprint

    b_hash = hashlib.sha256(jwk.replace(' ', '').encode("utf8")).digest()
    thumbprint = base64.urlsafe_b64encode(b_hash).decode().replace('=', '')

    logger.info(thumbprint)
    return thumbprint


def calc_txt_value(key_auth):
    b_hash = hashlib.sha256(key_auth.replace(' ', '').encode("utf8")).digest()
    txt_value = base64.urlsafe_b64encode(b_hash).decode().replace('=', '')

    logger.info(txt_value)
    return txt_value


# 判断域名格式是都正确 "^(?:[_a-z0-9](?:[_a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)?$"
def check_domain(domain):
    # 替换通配符，方便判断域名格式是否正确
    domain = domain.replace('*.', '_all_all_all_all')
    return re.match("^(?:[_a-z0-9](?:[_a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)?$", domain)


def check_email(email):
    return re.match(r'^[a-zA-Z0-9_!#$%&\'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)


###################################################################################


# ***********************************************************************************


# 初始化 lets api
def init_letsencrypt_api():
    logger.info('>>> 初始化 letsencrypt api')
    headers = {
        'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
        'accept': '*/*'
    }
    payload = None
    response = requests.request("GET", CA_LETSENCRYPT_V2, headers=headers, data=payload, verify=False)
    json_body = response.json()

    logger.info(f'http_header: {response.headers}')
    logger.info(f'json_body: {json_body}')

    global NEW_NONCE, NEW_ACCOUNT, NEW_ORDER, REVOKE_CERT, KEY_CHANGE
    NEW_NONCE = json_body['newNonce']
    NEW_ACCOUNT = json_body['newAccount']
    NEW_ORDER = json_body['newOrder']
    REVOKE_CERT = json_body['revokeCert']


def init_account_info(args):
    logger.info('>>> 初始化账户信息')

    global CA_EMAIL

    # 从 args 中获取邮箱
    for arg in args:
        if arg.startswith('--email'):
            email = arg.split('=')[1]
            # 检查域名格式
            if check_email(email):
                logger.info(f'邮箱: {email}')
                CA_EMAIL = email
            else:
                logger.error(f'!!! 邮箱格式错误: {email}')
                # sys.exit(1)
                # 抛出异常
                raise Exception(f'邮箱格式错误: {email}')

    if not CA_EMAIL:
        logger.error('!!! 请提供邮箱')
        # sys.exit(1)
        # 抛出异常
        raise Exception('请提供邮箱')

    return CA_EMAIL


# 创建账户私钥 
def create_account_key(account_key_path):
    logger.info('>>> 创建账户私钥')
    if os.path.exists(account_key_path) and os.path.getsize(account_key_path) > 0:
        logger.info(f'使用已有账户私钥: {account_key_path}')
        return

    # 生成一个P-256曲线的ECC私钥
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )

    logger.info(f'account.key: {pem}')

    # 将PEM格式的私钥保存到文件
    with open(account_key_path, "wb") as key_file:
        key_file.write(pem)

    if os.path.exists(account_key_path) and os.path.getsize(account_key_path) > 0:
        logger.info(f'账户私钥保存成功: {account_key_path}')
    else:
        logger.error('!!! 账户私钥保存失败')
        # sys.exit(1)
        raise Exception('账户私钥保存失败')


# 计算 jwk 
def calc_jwk(account_key_path):

    global JWK
    if JWK:
        return JWK

    logger.info('>>> 计算 jwk')

    # 读取account_key
    with open(account_key_path, 'r') as f:
        account_key = f.read()

    # 将account_key字符串转换为字节
    pem_key = account_key.encode()

    # 从PEM格式加载椭圆曲线私钥
    private_key = serialization.load_pem_private_key(
    pem_key, # PEM格式的密钥字节
    password=None, # 如果密钥未加密，密码为None
    backend=default_backend() # 默认的backend
    )

    # 确保加载的私钥是ECC类型的
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        # 获取公钥
        public_key = private_key.public_key()

    # 获取x和y坐标
    public_numbers = public_key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y

    logger.info(f'x: {x}, y: {y}')

    # 将x和y坐标转换为字节
    x_bytes = x.to_bytes(32, 'big')
    y_bytes = y.to_bytes(32, 'big')

    # 将x和y坐标转换为Base64编码 urlsafe_b64encode 去掉=号
    x64 = base64.urlsafe_b64encode(x_bytes).decode('utf-8').replace('=', '')
    y64 = base64.urlsafe_b64encode(y_bytes).decode('utf-8').replace('=', '')

    JWK = f'{{"crv": "P-256", "kty": "EC", "x": "{x64}", "y": "{y64}"}}'
    # JWK = json.dumps({"crv": "P-256", "kty": "EC", "x": x64, "y": y64})
    logger.info(f'JWK: {JWK}')
    return JWK


# 计算账户私钥的哈希值
def calc_accout_key_hash(account_key_path):
    logger.info('>>> 计算账户私钥的哈希值')

    # 创建SHA-256哈希对象
    hash_object = hashlib.sha256()

    # 正确的
    # 打开文件并读取二进制内容
    with open(account_key_path, 'rb') as file:
        # 逐块读取文件内容，以避免一次性加载大文件到内存
        for chunk in iter(lambda: file.read(4096), b""):
            hash_object.update(chunk)

    # 获取二进制的散列值
    binary_hash = hash_object.digest()

    # 将二进制散列值编码为Base64
    base64_hash = base64.b64encode(binary_hash).decode()
    logger.info(base64_hash)

    return base64_hash


# 注册账户
def reg_account():
    logger.info('>>> 注册账户')
    if os.path.exists(ACCOUNT_JSON) and os.path.getsize(ACCOUNT_JSON) > 0:
        logger.info(f'使用已有账户: {ACCOUNT_JSON}')
        return

    headers = {
        'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
        'accept': '*/*',
        'content-type': 'application/jose+json',
    }

    # {"protected": "eyJub25jZSI6ICJWYkhjR0t3bmFGRzFpMEhWbWFVRG9CVm5JSFFzUFU2VWZOWmhSZEdNaEZkVHFwdS1TMEEiLCAidXJsIjogImh0dHBzOi8vYWNtZS12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwgImFsZyI6ICJFUzI1NiIsICJqd2siOiB7ImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJteEhrRmhaNTQzLURlQktSYjBGNFpBeE9lLW9yRTFzREY5MFdrRDVRN09rIiwgInkiOiAibDVSM1o3eUEyOVVDR0J2d1dJR3dqTmthYjA3NXZDdUptZEFCbzNUT2taWSJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86ZW1haWw9ZXdlZmhlc3JoQGRzZ3NkLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ", "signature": "QT6RAG0qGxc35ShUGmWfqTH3XUgiX09jIc2xXWwFpHh7pZwbvkaflfPEM28OlK2ZPCMSsmDSqlY_YoAapCFOaQ"}
    # eyJub25jZSI6ICJWYkhjR0t3bmFGRzFpMEhWbWFVRG9CVm5JSFFzUFU2VWZOWmhSZEdNaEZkVHFwdS1TMEEiLCAidXJsIjogImh0dHBzOi8vYWNtZS12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwgImFsZyI6ICJFUzI1NiIsICJqd2siOiB7ImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJteEhrRmhaNTQzLURlQktSYjBGNFpBeE9lLW9yRTFzREY5MFdrRDVRN09rIiwgInkiOiAibDVSM1o3eUEyOVVDR0J2d1dJR3dqTmthYjA3NXZDdUptZEFCbzNUT2taWSJ9fQ
    # {"nonce": "VbHcGKwnaFG1i0HVmaUDoBVnIHQsPU6UfNZhRdGMhFdTqpu-S0A", "url": "https://acme-v02.api.letsencrypt.org/acme/new-acct", "alg": "ES256", "jwk": {"crv": "P-256", "kty": "EC", "x": "mxHkFhZ543-DeBKRb0F4ZAxOe-orE1sDF90WkD5Q7Ok", "y": "l5R3Z7yA29UCGBvwWIGwjNkab075vCuJmdABo3TOkZY"}}
    protected = f'{{"nonce": "{new_nonce()}", "url": "{NEW_ACCOUNT}", "alg": "ES256", "jwk": {calc_jwk(ACCOUNT_KEY)}}}'
    protected64 = base64.urlsafe_b64encode(protected.encode('utf-8')).decode('utf-8').replace('=', '')
    # eyJjb250YWN0IjogWyJtYWlsdG86ZW1haWw9ZXdlZmhlc3JoQGRzZ3NkLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ
    # {"contact": ["mailto:email=ewefhesrh@dsgsd.com"], "termsOfServiceAgreed": true}
    payload = f'{{"contact": ["mailto:email={CA_EMAIL}"], "termsOfServiceAgreed": true}}'
    payload64 = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('utf-8').replace('=', '')
    signature = sign_base64_url_replace(f'{protected64}.{payload64}', ACCOUNT_KEY)

    data_body = f'{{"protected":"{protected64}", "payload":"{payload64}", "signature":"{signature}"}}'
    logger.info(f'data_body: {data_body}')

    response = requests.request("POST", NEW_ACCOUNT, headers=headers, data=data_body, verify=False)
    http_header = response.headers
    json_body = response.text

    global SHARED_NONCE
    SHARED_NONCE = http_header['Replay-Nonce']

    if (response.status_code > 300) or ('location' not in http_header):
        logger.error(f'!!! 账户注册失败: {json_body}')
        # 退出
        # sys.exit(1)
        raise Exception(f'账户注册失败: {json_body}')

    # 保存到 account.json
    with open(ACCOUNT_JSON, 'w') as f:
        f.write(json_body)

    # 保存到 ca.conf
    with open(CA_CONF, 'a') as f:
        account_url = http_header["Location"] if 'Location' in http_header else http_header["location"]
        account_key_hash = calc_accout_key_hash(ACCOUNT_KEY)
        f.write(f"CA_EMAIL='{CA_EMAIL}'\n")
        f.write(f"ACCOUNT_URL='{account_url}'\n")
        f.write(f"CA_KEY_HASH='{account_key_hash}'\n")

    logger.info(f'账户注册成功: {json_body}')
    logger.info(f'账户注册成功: {ACCOUNT_JSON}')


# 初始化域名信息
def init_domain_info(args):
    logger.info('>>> 初始化域名信息')
    # domain = str(domain.encode('idna'), 'utf-8')

    # 从 args 中获取域名
    # 遍历 args，获取域名
    domains = []
    for arg in args:
        if arg.startswith('--domain') or arg.startswith('-d'):
            d = arg.split('=')[1]
            d = str(d.encode('idna'), 'utf-8')
            # 检查域名格式
            if check_domain(d):
                domains.append(d)
            else:
                logger.error(f'!!! 域名格式错误: {d}')
                # sys.exit(1)
                raise Exception(f'域名格式错误: {d}')

    if len(domains) == 0:
        logger.error('!!! 未指定域名')
        # sys.exit(1)
        raise Exception('未指定域名')

    # 第一个域名作为主域名
    global MAIN_DOMAIN
    MAIN_DOMAIN = domains[0]

    # 其余域名拼接到 ALT_DOMAINS
    global ALT_DOMAINS
    ALT_DOMAINS = ','.join(domains[1:])

    logger.info(f'主域名: {MAIN_DOMAIN}')
    logger.info(f'多域名: {ALT_DOMAINS}')

    # TODO add rsa
    global DOMAIN_KEY_RSA
    for arg in args:
        if arg.startswith('--rsa'):
            DOMAIN_KEY_RSA = True
            logger.info('使用 RSA 密钥')
            break

    global CERT_KEY_PATH, CSR_PATH, CSR_CONF_PATH, DOMAIN_CONF_PATH, CA_CERT_PATH, DOMAIN_CER_PATH, FULLCHAIN_CER_PATH

    # 创建目录，初始化路径
    domain_root = MAIN_DOMAIN.replace('*.', '')
    domain_home = os.path.abspath(domain_root)+('_rsa' if DOMAIN_KEY_RSA else '')  # TODO add rsa
    if not os.path.exists(domain_home):
        os.makedirs(domain_home)
    CERT_KEY_PATH = os.path.abspath(f'{domain_home}/{domain_root}.key')
    CSR_PATH = os.path.abspath(f'{domain_home}/{domain_root}.csr')
    CSR_CONF_PATH = os.path.abspath(f'{domain_home}/{domain_root}.csr.conf')
    DOMAIN_CONF_PATH = os.path.abspath(f'{domain_home}/{domain_root}.conf')
    CA_CERT_PATH = os.path.abspath(f'{domain_home}/ca.cer')
    DOMAIN_CER_PATH = os.path.abspath(f'{domain_home}/{domain_root}.cer')
    FULLCHAIN_CER_PATH = os.path.abspath(f'{domain_home}/fullchian.cer')


# 创建域名私钥 
def create_domain_key(domain_key_path):
    logger.info('>>> 创建域名私钥')
    if os.path.exists(domain_key_path) and os.path.getsize(domain_key_path) > 0:
        logger.info(f'使用已有域名私钥: {domain_key_path}')
        return

    # 生成一个P-256曲线的ECC私钥
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )

    logger.info(f'domain.key: {pem}')

    # 将PEM格式的私钥保存到文件
    with open(domain_key_path, "wb") as key_file:
        key_file.write(pem)

    if os.path.exists(domain_key_path) and os.path.getsize(domain_key_path) > 0:
        logger.info(f'域名私钥保存成功: {domain_key_path}')
    else:
        logger.error(f'!!! 域名私钥保存失败')
        # sys.exit(1)
        raise Exception('域名私钥保存失败')


# 创建域名私钥  RSA 2048
def create_domain_key_rsa(domain_key_path):
    logger.info('>>> 创建域名私钥 RSA 2048')
    if os.path.exists(domain_key_path) and os.path.getsize(domain_key_path) > 0:
        logger.info(f'使用已有域名私钥: {domain_key_path}')
        return

    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 私钥序列化
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    logger.info(f'domain.key: {pem}')

    # 将PEM格式的私钥保存到文件
    with open(domain_key_path, "wb") as key_file:
        key_file.write(pem)

    if os.path.exists(domain_key_path) and os.path.getsize(domain_key_path) > 0:
        logger.info(f'域名私钥保存成功: {domain_key_path}')
    else:
        logger.error(f'!!! 域名私钥保存失败')
        # sys.exit(1)
        raise Exception('域名私钥保存失败')


# 保存域名配置信息
def save_domain_conf(key, value):
    with open(DOMAIN_CONF_PATH, 'a') as f:
        f.write(f"{key}='{value}'\n")
        logger.info(f"保存域名配置信息: {key}='{value}'")


# 申请证书前的操作
def on_before_issue():
    if os.path.exists(DOMAIN_CONF_PATH) and os.path.getsize(DOMAIN_CONF_PATH) > 0:
        logger.info(f'使用已有domain.conf: {DOMAIN_CONF_PATH}')
        return

    le_domain = MAIN_DOMAIN
    le_alt = ALT_DOMAINS
    le_webroot = 'dns'
    le_api = CA_LETSENCRYPT_V2
    le_keylength = DOMAIN_KEY_RSA_LEN if DOMAIN_KEY_RSA else DEFAULT_DOMAIN_KEY_LENGTH   # TODO add rsa

    save_domain_conf('Le_Domain', le_domain)
    save_domain_conf('Le_Alt', le_alt)
    save_domain_conf('Le_Webroot', le_webroot)
    save_domain_conf('Le_API', le_api)
    save_domain_conf('Le_Keylength', le_keylength)


def send_new_order():
    logger.info('>>> 发送新订单')
    # 生成订单
    # {"nonce": "QSUQafWTdd_mPDRczjKr9jSBxJ5dlsAtGlPveqERlMk", "url": "https://acme.zerossl.com/v2/DV90/newOrder", "alg": "ES256", "kid": "https://acme.zerossl.com/v2/DV90/account/7p*****GhreJrg"}
    protected = f'{{"nonce": "{new_nonce()}", "url": "{NEW_ORDER}", "alg": "ES{ECC_KEY_LEN}", "kid": "{read_config("ACCOUNT_URL", CA_CONF)}"}}'
    protected64 = base64.urlsafe_b64encode(protected.encode()).decode().replace('=', '')

    # {"identifiers": [{"type":"dns","value":"yy.test.domain.com"},{"type":"dns","value":"*.yy.test.domain.com"},{"type":"dns","value":"zz.test.domain.com"},{"type":"dns","value":"*.zz.test.domain.com"}]}
    # 从 ALT_DOMAINS 拼接多域名 {"type":"dns","value":"yy.test.domain.com"}

    if ALT_DOMAINS:
        domains = '{"type":"dns","value":"'+(MAIN_DOMAIN+','+ALT_DOMAINS).replace(',', '"},{"type":"dns","value":"')+'"}'
    else:
        domains = '{"type":"dns","value":"'+MAIN_DOMAIN+'"}'


    payload = f'{{"identifiers": [{domains}]}}'
    payload64 = base64.urlsafe_b64encode(payload.encode()).decode().replace('=', '')

    # 签名
    signature = sign_base64_url_replace(f'{protected64}.{payload64}', ACCOUNT_KEY)

    data_body = f'{{"protected":"{protected64}", "payload":"{payload64}", "signature":"{signature}"}}'
    logger.info(f'data_body: {data_body}')

    headers = {
        'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
        'accept': '*/*',
        'content-type': 'application/jose+json',
    }

    response = requests.request("POST", NEW_ORDER, headers=headers, data=data_body, verify=False)
    http_header = response.headers
    json_body = response.json()

    logger.info(f'http_header: {http_header}')
    logger.info(f'json_body: {json_body}')

    global SHARED_NONCE
    SHARED_NONCE = http_header['Replay-Nonce']

    # 保存到 domain.conf
    Le_OrderFinalize = json_body['finalize']
    save_domain_conf('Le_OrderFinalize', Le_OrderFinalize)
    Le_LinkOrder = http_header['location']
    save_domain_conf('Le_LinkOrder', Le_LinkOrder)

    # 保存 authorizations
    # {"status":"pending","expires":"2024-10-24T11:22:14Z","identifiers":[{"type":"dns","value":"yy.test.domain.com"},{"type":"dns","value":"*.yy.test.domain.com"},{"type":"dns","value":"zz.test.domain.com"},{"type":"dns","value":"*.zz.test.domain.com"}],"authorizations":["https://acme.zerossl.com/v2/DV90/authz/rgp_d5FDn1haYmATDZ2eSw","https://acme.zerossl.com/v2/DV90/authz/PIFj9tVWsBesDQ3x1wTJlw","https://acme.zerossl.com/v2/DV90/authz/8KqEh55E1PU7kpMLLWGqPQ","https://acme.zerossl.com/v2/DV90/authz/M-HvXbB91BKZf8zVZne_vg"],"finalize":"https://acme.zerossl.com/v2/DV90/order/gVgxWlURMo_AxeohKkVl5g/finalize"}
    global authrs_for_domain
    for i in range(len(json_body['authorizations'])):
        domain = json_body['identifiers'][i]['value']
        authorization = json_body['authorizations'][i]
        authrs_for_domain[domain] = authorization
        logger.info(f"authorization: {domain+'='+authorization}")


def get_each_authorization():
    logger.info('>>> 获取每个授权')

    Le_Vlist = ''

    for domain, authorization in authrs_for_domain.items():
        # {"nonce": "QjObzzTr2ag0klh9etfewPHyu5bM67xbtrdkzQDbez4", "url": "https://acme.zerossl.com/v2/DV90/authz/rgp_d5FDn1haYmATDZ2eSw", "alg": "ES256", "kid": "https://acme.zerossl.com/v2/DV90/account/7p*****GhreJrg"}
        protected = f'{{"nonce": "{new_nonce()}", "url": "{authorization}", "alg": "ES{ECC_KEY_LEN}", "kid": "{read_config("ACCOUNT_URL", CA_CONF)}"}}'
        protected64 = base64.urlsafe_b64encode(protected.encode()).decode().replace('=', '')
        payload64 = ''
        signature = sign_base64_url_replace(f'{protected64}.{payload64}', ACCOUNT_KEY)

        data_body = f'{{"protected":"{protected64}", "payload":"{payload64}", "signature":"{signature}"}}'
        logger.info(f'data_body: {data_body}')

        headers = {
            'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
            'accept': '*/*',
            'content-type': 'application/jose+json'
        }

        response = requests.request("POST", authorization, headers=headers, data=data_body, verify=False)

        http_header = response.headers
        json_body = response.json()

        logger.info(f'http_header: {http_header}')
        logger.info(f'json_body: {json_body}')

        global SHARED_NONCE
        SHARED_NONCE = http_header['Replay-Nonce']

        # 此处默认 status 为 pending（待定），不考虑其他情况

        # {"identifier":{"type":"dns","value":"yy.test.domain.com"},"status":"pending","expires":"2024-08-25T11:22:13Z","challenges":[{"type":"http-01","url":"https://acme.zerossl.com/v2/DV90/chall/64plHUY3FyVgCCbCAmLKWQ","status":"pending","token":"zA1BLfiiF-B_EwdABf4ruGLIU8ynMi6PcuKkBmMmM6U"},{"type":"dns-01","url":"https://acme.zerossl.com/v2/DV90/chall/pshmanYqXNGZ3PeQE_CA9g","status":"pending","token":"B126WehfSpgJFBNOLX9lIH-2ofJQSRw9XLkTFlyICN8"}]}
        # dns 的 token 和 challenge
        token = chall = ''
        for i in (json_body['challenges']):
            if i['type'] == 'dns-01':
                token = i['token']
                chall = i['url']
                logger.info(f"token, chall: {token}, {chall}")
                break

        # KEY_AUTHORIZATION
        KEY_AUTHORIZATION = token + "." + calc_thumbprint(calc_jwk(ACCOUNT_KEY))  # token + "." + thumbprint
        logger.info(f"KEY_AUTHORIZATION: {KEY_AUTHORIZATION}")

        global txt_for_domain
        txt_for_domain[domain] = calc_txt_value(KEY_AUTHORIZATION)

        # Le_Vlist   dvlist="$d$sep$keyauthorization$sep$uri$sep$vtype$sep$_currentRoot$sep$_authz_url"
        #  vlist='pc.test.domain.com#4iQ9TL3Kthwwl9frKMu2mb2IWLIQ5UPS9ZWcCSBE66s.WGpZWjxY_PWYqYH0lWnrgFEFynFF_VSzd4eL7MmK-4Y#https://acme.zerossl.com/v2/DV90/chall/9i-4dZO1uDtOivQEHLMdIQ#dns-01#dns#https://acme.zerossl.com/v2/DV90/authz/hr3DiLmg7uK87Kopf3Xd0A,'
        sep = '#'
        dvsep = ','
        Le_Vlist += f'{domain}{sep}{KEY_AUTHORIZATION}{sep}{chall}{sep}dns-01{sep}dns{sep}{authorization}{dvsep}'

    logger.info(f'Le_Vlist: {Le_Vlist}')

    # 保存到 domain.conf
    save_domain_conf('Le_Vlist', Le_Vlist)


    # txt记录
    logger.info('############################################################################')
    logger.info('#### 请添加以下TXT记录到域名DNS解析中：')
    for domain, txt in txt_for_domain.items():
        logger.info(f'#### {"_acme-challenge."+domain.replace("*.","")}:  {txt}')
    logger.info('############################################################################')


def continue_verify(domain_conf_path):
    logger.info('>>> 继续验证')

    # 1 从 domain.conf 文件中获取 challenges authrs 信息
    vlist = read_config('Le_Vlist', domain_conf_path)
    logger.info(f'vlist: {vlist}')

    domain_infos = vlist.split(',')[:-1]
    for domain_info in domain_infos:
        info = domain_info.split('#')
        logger.info(f'info: {info}')
        authrs_for_domain[info[0]] = info[5]
        challs_for_domain[info[0]] = info[2]
    logger.info(f'authrs_for_domain: {authrs_for_domain}')
    logger.info(f'challs_for_domain: {challs_for_domain}')

    # 2 challenge
    for domain, chall_url in challs_for_domain.items():
        logger.info(f'>>> >>> 域名 {domain} 的 challenge')

        protected = f'{{"nonce": "{new_nonce()}", "url": "{chall_url}", "alg": "ES{ECC_KEY_LEN}", "kid": "{read_config("ACCOUNT_URL", CA_CONF)}"}}' #.format("new_nonce()", chall_url, ECC_KEY_LEN, read_config("ACCOUNT_URL", CA_CONF))
        protected64 = base64.urlsafe_b64encode(protected.encode()).decode().rstrip("=")
        payload64 = base64.urlsafe_b64encode('{}'.encode()).decode().rstrip("=")
        signature = sign_base64_url_replace(protected64 + '.' + payload64, ACCOUNT_KEY)
        data_body = f'{{"protected": "{protected64}", "payload": "{payload64}", "signature": "{signature}"}}' #.format(protected64, payload64, signature)
        logger.info(f'data_body: {data_body}')

        headers = {
            'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
            'accept': '*/*',
            'content-type': 'application/jose+json'
        }
        response = requests.request("POST", chall_url,
                                     headers=headers, data=data_body, verify=False)

        http_header = response.headers
        json_body = response.json()
        logger.info(f'http_header: {http_header}')
        logger.info(f'json_body: {json_body}')

        global SHARED_NONCE
        SHARED_NONCE = http_header['Replay-Nonce']
        status = json_body['status']

        # status: processing, invalid, valid
        if status == 'invalid':
            logger.error(f'!!! challenge 失败: {json_body}')
            raise Exception(f'challenge 失败: {json_body}')
        elif status == 'valid':
            logger.info(f'域名 {domain} 验证成功')
            continue
        elif status == 'processing' or status == 'pending': # TODO challenge status
            # 3 验证 dns 记录
            logger.info('>>> >>> >>> 验证 DNS 记录')
            while not status == 'valid':
                auth_url = authrs_for_domain[domain]
                protected = f'{{"nonce": "{new_nonce()}", "url": "{auth_url}", "alg": "ES{ECC_KEY_LEN}", "kid": "{read_config("ACCOUNT_URL", CA_CONF)}"}}'
                protected64 = base64.urlsafe_b64encode(protected.encode()).decode().rstrip("=")
                payload64 = ''
                signature = sign_base64_url_replace(protected64 + '.' + payload64, ACCOUNT_KEY)
                data_body = f'{{"protected": "{protected64}", "payload": "{payload64}", "signature": "{signature}"}}'

                headers = {
                    'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
                    'accept': '*/*',
                    'content-type': 'application/jose+json'
                }

                response = requests.request("POST", auth_url,
                                             headers=headers, data=data_body, verify=False)

                http_header = response.headers
                json_body = response.json()
                logger.info(f'http_header: {http_header}')
                logger.info(f'json_body: {json_body}')

                SHARED_NONCE = http_header['Replay-Nonce']

                status = json_body['status']
                if status == 'invalid':
                    logger.error(f'!!! 验证失败: {json_body}')
                    raise Exception(f'验证失败: {json_body}')

                logger.info('>>> >>> >>> >>> 等待 10s...')
                time.sleep(10)
        else:
            logger.error(f'!!! challenge未知状态: {status}')
            raise Exception(f'challenge未知状态: {status}')


def create_csr(domain_key_path,domain_conf_path, csr_conf_path, csr_path):
    logger.info('>>> 生成 CSR')

    # 1 创建 domain.csr.conf
    if os.path.exists(csr_path) and os.path.getsize(csr_path) > 0:
        logger.info(f'使用已有 domain.csr: {csr_path}')
        return

    # 新建 domain.csr 空文件
    with open(csr_conf_path, 'w') as f:
        f.write('')

    # # 读取 domain.conf
    MAIN_DOMAIN = read_config('Le_Domain', domain_conf_path)
    ALT_DOMAINS = read_config('Le_Alt', domain_conf_path)

    if ALT_DOMAINS:
        domains = f'{MAIN_DOMAIN},{ALT_DOMAINS}'
        # subjectAltName=DNS:yy.test.domain.com,DNS:*.yy.test.domain.com,DNS:zz.test.domain.com,DNS:*.zz.test.domain.com
        subject_alt_name = ','.join([f'DNS:{d}' for d in domains.split(',')])
    else:
        domains = MAIN_DOMAIN
        subject_alt_name = f'DNS:{MAIN_DOMAIN}'

    # 写入 domain.csr.conf
    with open(csr_conf_path, 'w') as f:
        f.write("[ req_distinguished_name ]\n[ req ]\n" +
                "distinguished_name = req_distinguished_name\n" +
                "req_extensions = v3_req\n" +
                "[ v3_req ]\n" +
                "extendedKeyUsage=serverAuth,clientAuth\n" +
                f"\nsubjectAltName={subject_alt_name}"
                )

    # 2 生成 domain.csr
    with open(domain_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # 设置CSR的主题（Distinguished Name）
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, MAIN_DOMAIN),
    ])

    # 设置CSR的扩展（这里只设置subjectAltName）
    # 添加多个DNS名称
    # alt_names = [x509.DNSName("yy.test.domain.com"), x509.DNSName("*.yy.test.domain.com"), x509.DNSName("zz.test.domain.com"), x509.DNSName("*.zz.test.domain.com")]
    alt_names = [x509.DNSName(d) for d in domains.split(',')]

    # 扩展
    san = x509.SubjectAlternativeName(alt_names)

    eku_extension = x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.SERVER_AUTH,  # TLS Web Server Authentication
        ExtendedKeyUsageOID.CLIENT_AUTH,  # TLS Web Client Authentication
    ])

    # 创建CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(eku_extension, critical=False)
            .add_extension(san, critical=False)
            .sign(private_key, hashes.SHA256(), default_backend())
    )

    # 将CSR保存到文件
    logger.info(csr.public_bytes(serialization.Encoding.PEM).decode())
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    if os.path.exists(csr_path) and os.path.getsize(csr_path) > 0:
        logger.info(f'生成 CSR 成功: {csr_path}')


def finalize_order(domain_conf_path, csr_path):
    logger.info('>>> 发送 csr')

    order_finalize_url = read_config('Le_OrderFinalize', domain_conf_path)
    link_order_url = read_config('Le_LinkOrder', domain_conf_path)

    # 1 读取 csr
    with open(csr_path, 'r') as f:
        csr = f.read()
    # 替换开头和结尾，使用正则替换
    csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----', '').replace('-----END CERTIFICATE REQUEST-----', '').replace('\r ', '').replace('\n', '').replace(' ', '')
    der = base64.urlsafe_b64encode(base64.b64decode(csr)).decode().rstrip('=')

    # 2 发送 csr
    logger.info(f'>>> >>> 发送 csr: {der}')
    protected = f'{{"nonce": "{new_nonce()}", "url": "{order_finalize_url}", "alg": "ES{ECC_KEY_LEN}", "kid": "{read_config("ACCOUNT_URL", CA_CONF)}"}}'
    payload = f'{{"csr": "{der}"}}'
    protected64 = base64.urlsafe_b64encode(protected.encode()).decode().rstrip('=')
    payload64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
    signature = sign_base64_url_replace(f'{protected64}.{payload64}', ACCOUNT_KEY)
    data_body = f'{{"protected": "{protected64}", "payload": "{payload64}", "signature": "{signature}"}}'

    headers = {
        'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
        'accept': '*/*',
        'content-type': 'application/jose+json'
    }

    response = requests.request("POST", order_finalize_url, headers=headers, data=data_body, verify=False)
    http_header = response.headers
    json_body = response.json()
    logger.info(f'http_header: {http_header}')
    logger.info(f'json_body: {json_body}')

    global SHARED_NONCE
    SHARED_NONCE = http_header['Replay-Nonce']

    status = json_body['status']

    if status == 'processing':
        link_order_url = http_header['Location']
    elif status == 'valid':
        link_cert = json_body['certificate']
        save_domain_conf('Le_LinkCert', link_cert)
        logger.info('\n######################################################\n####            申请成功，开始下发证书              ####\n######################################################')
        return # letenc.. 可能不需要下面的流程 send link order
    else:
        logger.error(f'超出本程序处理范围: {status}，忽略错误，尝试下一步')
        # raise Exception(f'超出本程序处理范围: {status}')

    # 3 send link order, util status=valid
    while not status == 'valid':
        logger.info(f'>>> >>> >>> send link order')
        protected = f'{{"nonce": "{new_nonce()}", "url": "{link_order_url}", "alg": "ES{ECC_KEY_LEN}", "kid": "{read_config("ACCOUNT_URL", CA_CONF)}"}}'
        protected64 = base64.urlsafe_b64encode(protected.encode()).decode().replace('=', '')
        payload64 = ''
        signature = sign_base64_url_replace(f'{protected64}.{payload64}', ACCOUNT_KEY)
        data_body = f'{{"protected": "{protected64}", "payload": "{payload64}", "signature": "{signature}"}}'

        response = requests.request("POST", link_order_url, headers=headers, data=data_body, verify=False)
        http_header = response.headers
        json_body = response.json()
        logger.info(f'http_header: {http_header}')
        logger.info(f'json_body: {json_body}')

        SHARED_NONCE = http_header['Replay-Nonce']
        status = json_body['status']

        if status == 'processing':
            logger.info('>>> >>> >>> >>> 等待 10s')
            time.sleep(10)
        elif status == 'invalid':
            logger.error('!!! 出错了')
            raise Exception('出错了')
        elif status == 'valid':
            link_cert = json_body['certificate']
            save_domain_conf('Le_LinkCert', link_cert)
            logger.info('\n######################################################\n####            申请成功，开始下发证书              ####\n######################################################')


def download_cert(domain_conf_path, fullchain_path):
    logger.info('>>> 下载证书')

    link_cert = read_config('Le_LinkCert', domain_conf_path)

    protected = f'{{"nonce": "{new_nonce()}", "url": "{link_cert}", "alg": "ES{ECC_KEY_LEN}", "kid": "{read_config("ACCOUNT_URL", CA_CONF)}"}}'
    protected64 = base64.urlsafe_b64encode(protected.encode()).decode().replace('=', '')
    payload64 = ''
    signature = sign_base64_url_replace(f'{protected64}.{payload64}', ACCOUNT_KEY)
    data_body = f'{{"protected": "{protected64}", "payload": "{payload64}", "signature": "{signature}"}}'

    headers = {
        'user-agent': 'acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)',
        'accept': '*/*',
        'content-type': 'application/jose+json'
    }

    response = requests.request("POST", link_cert, headers=headers, data=data_body, verify=False)

    http_header = response.headers
    text_body = response.text
    logger.info(f'http_header: {http_header}')
    logger.info(f'text_body: {text_body}')

    # 保存证书
    with open(fullchain_path, 'w') as f:
        f.write(text_body)

    # 加载证书
    certificate = x509.load_pem_x509_certificate(text_body.encode(), default_backend())

    # 保存时间到domain.conf
    Le_CertCreateTime = int(certificate.not_valid_before_utc.timestamp())
    Le_CertCreateTimeStr = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(Le_CertCreateTime))
    Le_NextRenewTime = Le_CertCreateTime + 60 * 60 * 24 * 60
    Le_NextRenewTimeStr = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(Le_NextRenewTime))
    save_domain_conf('Le_CertCreateTime', Le_CertCreateTime)
    save_domain_conf('Le_CertCreateTimeStr', Le_CertCreateTimeStr)
    save_domain_conf('Le_NextRenewTime', Le_NextRenewTime)
    save_domain_conf('Le_NextRenewTimeStr', Le_NextRenewTimeStr)

    if os.path.exists(fullchain_path) and os.path.getsize(fullchain_path) > 0:
        logger.info('######################################################')
        logger.info('###########       证书下载成功         #################')
        logger.info(f'####  完整证书: {fullchain_path}')
        logger.info(f'####  私钥: {CERT_KEY_PATH}')
        logger.info('######################################################')
    else:
        logger.error('!!! 证书下载失败')
        raise Exception('证书下载失败')


def check_args(args):
    # 合法参数 issue renew continue --domain --email --rsa
    for arg in args[1:]:
        if arg[2:arg.find('=')] not in ['domain', 'email', 'rsa']:
            logger.error(f'!!! 参数错误: {arg}')
            raise Exception('参数错误')
    return True




# ***********************************************************************************
#
#       @author: ssldog.com
#       @date: 2024-07-25
#
#      * 1 checkRequiredExe()                    检查运行环境要求，检查系统os，检查curl和openssl，配置其路径
#      * 3 initZerosslApi()                      获取zerosslApi，配置nonce、account、order等相关api
#      * 2 createAccountKey() & calcJwk()          创建账户私钥，保存到 account.key，然后得到 jwk
#      * 4 getEabKid()                           提交邮箱，获取eab_kid，保存email、eab_key_id、account_url等信息到 ca.conf
#      * 5 regAccount()                          注册账户，提交公钥和eab_kid。获得账户信息，保存到 account.json
#      * 6 initDomainInfo(args)                  配置域名相关信息
#      * 7 createDomainKey() & onBeforeIssue()     执行申请证书前的操作，创建域名私钥./domainName/domainName.key，保存申请域名的配置到./domain/domain.conf
#      * 8 sendNewOrder()                        开始申请证书，提交 id、domain 等信息，获取 authorizations url，保存到 authrsForDomain 中。        acme.sh => STEP 1, Ordering a Certificate
#      * 9 getEachAuthorizations()               获取每个域名token，token和thumbprint组成KEY_AUTHORIZATION；保存 Le_Vlist（包含challengeUrl） 到 domain.conf 。 acme.sh => STEP 2, Get the authorizations of each domain
#      * 10 continueVerify(DOMAIN_CONF)          继续验证dns记录，完成申请证书
#      * 11 createCsr()                          创建 domain.csr    acme.sh => if ! _createcsr "$_main_domain" "$_alt_domains" "$CERT_KEY_PATH" "$CSR_PATH" "$DOMAIN_SSL_CONF"; then
#      * 12 finalizeOrder()                      完成申请证书最后一步 acme.sh => Lets finalize the order. > Order status is processing, lets sleep and retry. >   Order status is valid.
#      * 13 downloadCert()                       下载证书
#      * 14 extractCert()                        提取与转换，非必要，没有实现
#
#      和 Acme2J(https://github.com/ssldog-com/Acme2J) 的流程基本相同
#
if __name__ == '__main__':
    author = "\n              _       _\n" + "  ___   ___  | |   __| |   ___     __ _        ___    ___    _ __ __ _\n" + " / __| / __| | |  / _  |  / _ \\   / _  |      / __|  / _ \\  |  _   _  |\n" + " \\__ \\ \\__ \\ | | | (_| | | (_) | | (_| |  _  | (__  | (_) | | | | | | |\n" + " |___/ |___/ |_|  \\__,_|  \\___/   \\__, | (_)  \\___|  \\___/  |_| |_| |_|\n" + "                                  |___/"
    logger.info(author)
    # logger.info('>>> 开始申请证书')

    # args 的格式 [option/操作(issue, continue, renew), --domain=域名, --domain=域名1, --domain=域名2, 其余域名..., --email=邮箱, --rsa(可选)]
    args = sys.argv[1:]
    args = list(dict.fromkeys(args))
    logger.info(f'args: {args}')

    check_args(args)


    option = args[0]

    if option == 'issue':
        logger.info('>>> 开始申请证书')

        init_domain_info(args)
        init_account_info(args)

        if os.path.exists(DOMAIN_CONF_PATH):
            logger.info(f'>>> 已存在证书申请信息，请使用其他操作，或者删除 {MAIN_DOMAIN} 文件夹')
            raise Exception(f'已存在证书申请信息，请使用其他操作，或者删除 {MAIN_DOMAIN} 文件夹')

        init_letsencrypt_api()
        create_account_key(ACCOUNT_KEY)
        calc_jwk(ACCOUNT_KEY)
        # get_eab_kid() # zerossl
        reg_account()

        # TODO add rsa
        if DOMAIN_KEY_RSA:
            create_domain_key_rsa(CERT_KEY_PATH);
        else:
            create_domain_key(CERT_KEY_PATH)

        on_before_issue()
        send_new_order()
        get_each_authorization()

        args[0] = 'continue'
        logger.info(f'>>> 下一步: {" ".join(args)}')

    elif option == 'continue':
        logger.info('>>> 继续验证dns记录，完成申请证书')

        init_domain_info(args)
        init_account_info(args)

        init_letsencrypt_api()

        continue_verify(DOMAIN_CONF_PATH)
        create_csr(domain_key_path=CERT_KEY_PATH,domain_conf_path=DOMAIN_CONF_PATH,csr_conf_path=CSR_CONF_PATH,csr_path=CSR_PATH)
        finalize_order(DOMAIN_CONF_PATH, CSR_PATH)
        download_cert(DOMAIN_CONF_PATH, DOMAIN_CER_PATH)

    elif option == 'renew':
        logger.info('>>> 开始续期证书')

        init_domain_info(args)
        init_account_info(args)

        init_letsencrypt_api()
        create_account_key(ACCOUNT_KEY)
        calc_jwk(ACCOUNT_KEY)
        # get_eab_kid() # zerossl
        reg_account()

        # 重命名原来的 domain.conf 和 domian.cer
        os.rename(DOMAIN_CONF_PATH, f'{DOMAIN_CONF_PATH}.{time.strftime("%Y%m%d%H%M%S")}')
        os.rename(DOMAIN_CER_PATH, f'{DOMAIN_CER_PATH}.{time.strftime("%Y%m%d%H%M%S")}')

        # TODO add rsa
        if DOMAIN_KEY_RSA:
            create_domain_key_rsa(CERT_KEY_PATH);
        else:
            create_domain_key(CERT_KEY_PATH)

        on_before_issue()
        send_new_order()
        get_each_authorization()

        args[0] = 'continue'
        logger.info(f'>>> 下一步: {" ".join(args)}')

    else:
        logging.error('未知操作')
        raise Exception('未知操作')




    # # 方法                                                # 必要参数，测试时可自行提供
    #
    # # account
    # init_zerossl_api()                                   # CA_ZEROSSL
    # create_account_key(ACCOUNT_KEY)                       # ACCOUNT_KEY
    # calc_jwk(ACCOUNT_KEY)                                 # ACCOUNT_KEY
    # get_eab_kid()                                        # CA_EMAIL CA_CONF
    # reg_account()                                        # CA_EAB_KEY_ID, CA_EAB_HMAC_KEY, NEW_ACCOUNT, calc_jkw(ACCOUNT_KEY), ACCOUNT_JSON
    #
    # # domain
    # create_domain_key(CERT_KEY_PATH)                       # CERT_KEY_PATH
    # on_before_issue()                                     # DOMAIN_CONF_PATH MAIN_DOMAIN ALT_DOMAINS
    # send_new_order()                                      #MAIN_DOMAIN, ALT_DOMAINS, NEW_ORDER, CA_CONF, ACCOUNT_KEY, DOMAIN_CONF,
    # get_each_authorization()                              # CA_CONF authrs_for_domain, DOMAIN_CONF,
    # continue_verify(DOMAIN_CONF_PATH)                        #CA_CONF  DOMAIN_CONF
    # create_csr(domain_key_path=CERT_KEY_PATH,domain_conf_path=DOMAIN_CONF_PATH,csr_conf_path=CSR_CONF_PATH,csr_path=CSR_PATH)
    # finalize_order(DOMAIN_CONF_PATH, CSR_PATH)            # CA_CONF DOMAIN_CONF_PATH CSR_PATH
    # download_cert(DOMAIN_CONF_PATH, DOMAIN_CER_PATH)      # CA_CONF DOMAIN_CONF_PATH DOMAIN_CER_PATH
    #
    #
    #















