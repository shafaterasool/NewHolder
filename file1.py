import json
import os
import face_recognition
import cv2
import numpy as np
import hashlib
import binascii
import time
import requests
import random
import base64
import getpass
from typing import Dict, Optional, Tuple, List
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address
from hexbytes import HexBytes
from web3 import Web3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Blockchain rpc and SC
RPC_URL = "https://lb.drpc.org/ogrpc?network=sepolia&dkey=Av1D-w0zy029hxogqiYpAoJho_idRHoR8JwixpZiEquA"
CONTRACT_ADDRESS = "0xfB5E4033246E11851d9AC9f19109F734400f2Fc0"

FACE_DATA_FILE = "face_data.enc"
FACE_SALT_FILE = "face_salt.dat"
WALLETS_DIR = "wallets"
WALLET_SALT_FILE = "wallet_salt.dat"

# Abi from SC
CONTRACT_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "student", "type": "address"},
            {"indexed": True, "internalType": "bytes32", "name": "hash", "type": "bytes32"}
        ],
        "name": "CredentialIssued",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "student", "type": "address"}
        ],
        "name": "CredentialRevoked",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "student", "type": "address"},
            {"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"}
        ],
        "name": "issueCredential",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "student", "type": "address"}
        ],
        "name": "revokeCredential",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "", "type": "address"}],
        "name": "credentials",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "issuer",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "student", "type": "address"},
            {"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"}
        ],
        "name": "verifyCredential",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]

NETWORKS = {
    'mainnet': {
        'rpc_url': 'https://cloudflare-eth.com',
        'chain_id': 1,
        'native_asset': 'ETH'
    },
    'sepolia': {
        'rpc_url': 'https://lb.drpc.org/ogrpc?network=sepolia&dkey=Av1D-w0zy029hxogqiYpAoJho_idRHoR8JwixpZiEquA',
        'chain_id': 11155111,
        'native_asset': 'Sepolia-ETH'
    }
}

# ==================== WALLET PERSISTENT STORAGE ====================

class WalletStorage:
    """Handles encrypted persistent storage of wallet data"""
    
    @staticmethod
    def _ensure_wallets_directory():
        """Create wallets directory if it doesn't exist"""
        if not os.path.exists(WALLETS_DIR):
            os.makedirs(WALLETS_DIR)
            print("📁 Created wallet storage directory.")
    
    @staticmethod
    def _get_or_create_wallet_salt() -> bytes:
        """Get or create salt for wallet encryption"""
        if os.path.exists(WALLET_SALT_FILE):
            with open(WALLET_SALT_FILE, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(32)
            with open(WALLET_SALT_FILE, 'wb') as f:
                f.write(salt)
            return salt
    
    @staticmethod
    def _derive_wallet_key(username: str, password: str) -> bytes:
        """Derive encryption key from username and password"""
        salt = WalletStorage._get_or_create_wallet_salt()
        combined = f"{username}:{password}".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,  # Higher iterations for wallet security
        )
        key = kdf.derive(combined)
        return base64.urlsafe_b64encode(key)
    
    @staticmethod
    def _get_wallet_file_path(username: str) -> str:
        """Get the file path for a user's wallet"""
        WalletStorage._ensure_wallets_directory()
        username_hash = hashlib.sha256(username.encode()).hexdigest()[:16]
        return os.path.join(WALLETS_DIR, f"wallet_{username_hash}.enc")
    
    @staticmethod
    def save_wallet(username: str, password: str, wallet_data: dict) -> bool:
        """Save wallet data with encryption"""
        try:
            key = WalletStorage._derive_wallet_key(username, password)
            fernet = Fernet(key)
            
            # Convert private key bytes to hex for JSON serialization
            wallet_to_save = wallet_data.copy()
            if isinstance(wallet_to_save.get('private_key'), bytes):
                wallet_to_save['private_key'] = wallet_to_save['private_key'].hex()
            
            json_data = json.dumps(wallet_to_save)
            encrypted = fernet.encrypt(json_data.encode())
            
            file_path = WalletStorage._get_wallet_file_path(username)
            with open(file_path, 'wb') as f:
                f.write(encrypted)
            
            print("💾 Wallet data encrypted and saved to disk.")
            return True
        except Exception as e:
            print(f"⚠️  Error saving wallet: {e}")
            return False
    
    @staticmethod
    def load_wallet(username: str, password: str) -> Optional[dict]:
        """Load and decrypt wallet data"""
        try:
            file_path = WalletStorage._get_wallet_file_path(username)
            
            if not os.path.exists(file_path):
                return None
            
            key = WalletStorage._derive_wallet_key(username, password)
            fernet = Fernet(key)
            
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted = fernet.decrypt(encrypted_data)
            wallet_data = json.loads(decrypted.decode())
            
            # Convert private key back to bytes
            if isinstance(wallet_data.get('private_key'), str):
                wallet_data['private_key'] = bytes.fromhex(wallet_data['private_key'])
            
            print("📂 Wallet data loaded from disk.")
            return wallet_data
            
        except Exception as e:
            print(f"⚠️  Error loading wallet (wrong password?): {e}")
            return None
    
    @staticmethod
    def wallet_exists(username: str) -> bool:
        """Check if a wallet file exists for the user"""
        file_path = WalletStorage._get_wallet_file_path(username)
        return os.path.exists(file_path)
    
    @staticmethod
    def delete_wallet(username: str, password: str) -> bool:
        """Delete wallet file after password verification"""
        try:
            # Verify password by trying to load
            wallet = WalletStorage.load_wallet(username, password)
            if wallet is None:
                print("❌ Invalid password or wallet not found.")
                return False
            
            file_path = WalletStorage._get_wallet_file_path(username)
            os.remove(file_path)
            print("🗑️  Wallet deleted from disk.")
            return True
        except Exception as e:
            print(f"⚠️  Error deleting wallet: {e}")
            return False

# ==================== CREDENTIAL MANAGER ====================

class CredentialManager:
    """Manages credentials on blockchain"""
    
    def __init__(self, wallet):
        self.wallet = wallet
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
        if not self.w3.is_connected():
            raise ConnectionError("Failed to connect to blockchain")
        self.contract = self.w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    
    def create_credential_hash(self, credential_data: dict) -> str:
        credential_string = json.dumps(credential_data, sort_keys=True)
        return self.w3.keccak(text=credential_string).hex()
    
    def issue_credential_onchain(self, credential_data: dict) -> bool:
        try:
            cred_hash = self.create_credential_hash(credential_data)
            cred_hash_bytes = bytes.fromhex(cred_hash[2:])
            
            print(f"\n📝 Issuing credential on blockchain...")
            print(f"Credential Hash: {cred_hash}")
            
            nonce = self.w3.eth.get_transaction_count(self.wallet.wallet_data['address'])
            
            tx = self.contract.functions.issueCredential(
                to_checksum_address(self.wallet.wallet_data['address']),
                cred_hash_bytes
            ).build_transaction({
                'chainId': self.wallet.blockchain.chain_id,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': nonce,
            })
            
            signed_tx = self.w3.eth.account.sign_transaction(
                tx, 
                private_key=self.wallet.wallet_data['private_key']
            )
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"Transaction sent! Hash: {tx_hash.hex()}")
            print("Waiting for confirmation...")
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
            
            if receipt['status'] == 1:
                print("✅ Credential issued successfully on blockchain!")
                return True
            else:
                print("❌ Transaction failed!")
                return False
                
        except Exception as e:
            print(f"❌ Error issuing credential: {e}")
            return False
    
    def get_credential_from_chain(self) -> Optional[str]:
        try:
            student_address = to_checksum_address(self.wallet.wallet_data['address'])
            stored_hash = self.contract.functions.credentials(student_address).call()
            
            if isinstance(stored_hash, int):
                stored_hash_hex = format(stored_hash, "064x")
            elif isinstance(stored_hash, bytes):
                stored_hash_hex = stored_hash.hex()
            else:
                stored_hash_hex = stored_hash.lower().replace("0x", "")
            
            if stored_hash_hex != "0" * 64:
                return "0x" + stored_hash_hex
            return None
            
        except Exception as e:
            print(f"❌ Error retrieving credential: {e}")
            return None
    
    def revoke_credential(self) -> bool:
        try:
            print(f"\n🗑️  Revoking credential on blockchain...")
            
            nonce = self.w3.eth.get_transaction_count(self.wallet.wallet_data['address'])
            
            tx = self.contract.functions.revokeCredential(
                to_checksum_address(self.wallet.wallet_data['address'])
            ).build_transaction({
                'chainId': self.wallet.blockchain.chain_id,
                'gas': 100000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': nonce,
            })
            
            signed_tx = self.w3.eth.account.sign_transaction(
                tx, 
                private_key=self.wallet.wallet_data['private_key']
            )
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"Transaction sent! Hash: {tx_hash.hex()}")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
            
            if receipt['status'] == 1:
                print("✅ Credential revoked successfully!")
                return True
            else:
                print("❌ Transaction failed!")
                return False
                
        except Exception as e:
            print(f"❌ Error revoking credential: {e}")
            return False

# ==================== ENCRYPTION ====================

class FaceDataEncryption:
    
    @staticmethod
    def _get_or_create_salt() -> bytes:
        if os.path.exists(FACE_SALT_FILE):
            with open(FACE_SALT_FILE, 'rb') as f:
                return f.read()
        else:
            salt = os.urandom(32)
            with open(FACE_SALT_FILE, 'wb') as f:
                f.write(salt)
            return salt
    
    @staticmethod
    def _derive_key(password: str = "system_master_key") -> bytes:
        salt = FaceDataEncryption._get_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)
    
    @staticmethod
    def encrypt_data(data: dict) -> bytes:
        try:
            key = FaceDataEncryption._derive_key()
            fernet = Fernet(key)
            json_data = json.dumps(data)
            return fernet.encrypt(json_data.encode())
        except Exception as e:
            print(f"Encryption error: {e}")
            raise
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes) -> dict:
        try:
            key = FaceDataEncryption._derive_key()
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_data)
            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"Decryption error: {e}")
            raise

# ==================== LIVENESS DETECTION ====================

class LivenessDetector:
    
    @staticmethod
    def detect_blink(frame) -> bool:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
        
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        
        for (x, y, w, h) in faces:
            roi_gray = gray[y:y+h, x:x+w]
            eyes = eye_cascade.detectMultiScale(roi_gray)
            return len(eyes) < 2
        
        return False
    
    @staticmethod
    def request_random_action() -> str:
        actions = ["blink", "turn_left", "turn_right"]
        return random.choice(actions)
    
    @staticmethod
    def verify_action(action: str, frames: list) -> bool:
        if action == "blink":
            blink_detected = False
            for frame in frames:
                if LivenessDetector.detect_blink(frame):
                    blink_detected = True
                    break
            return blink_detected
        
        elif action in ["turn_left", "turn_right"]:
            if len(frames) < 2:
                return False
            
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            positions = []
            
            for frame in frames:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.3, 5)
                if len(faces) > 0:
                    x, y, w, h = faces[0]
                    positions.append(x + w // 2)
            
            if len(positions) < 2:
                return False
            
            movement = positions[-1] - positions[0]
            if action == "turn_left" and movement < -20:
                return True
            if action == "turn_right" and movement > 20:
                return True
            
            return False
        
        return False

# ==================== BLOCKCHAIN MANAGER ====================

class BlockchainManager:
    def __init__(self, network_name: str):
        self.network = NETWORKS.get(network_name)
        if not self.network:
            raise ValueError(f"Unsupported network: {network_name}")
        self.rpc_url = self.network['rpc_url']
        self.chain_id = self.network['chain_id']
        self.native_asset = self.network['native_asset']

    def _make_rpc_call(self, method: str, params: list = None) -> dict:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}
        try:
            response = requests.post(self.rpc_url, json=payload, timeout=15)
            response.raise_for_status()
            json_response = response.json()
            if 'error' in json_response:
                raise ValueError(f"RPC Error: {json_response['error']['message']}")
            return json_response
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to connect to RPC endpoint: {e}")

    def get_balance(self, address: str) -> float:
        result = self._make_rpc_call("eth_getBalance", [address, "latest"])
        if 'result' in result:
            balance_wei = int(result['result'], 16)
            return balance_wei / 10**18
        raise ValueError("Failed to get balance.")

    def get_transaction_count(self, address: str) -> int:
        result = self._make_rpc_call("eth_getTransactionCount", [address, "latest"])
        if 'result' in result:
            return int(result['result'], 16)
        raise ValueError("Failed to get transaction count.")

    def send_transaction(self, private_key: bytes, to_address: str, amount: float, gas_limit: int) -> str:
        account = Account.from_key(private_key)
        nonce = self.get_transaction_count(account.address)
        gas_price_result = self._make_rpc_call("eth_gasPrice")
        gas_price = int(gas_price_result['result'], 16)
        tx = {
            'chainId': self.chain_id,
            'to': to_checksum_address(to_address),
            'value': int(amount * 10**18),
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': nonce,
        }
        signed_tx = account.sign_transaction(tx)
        send_result = self._make_rpc_call("eth_sendRawTransaction", [signed_tx.raw_transaction.hex()])
        if 'result' in send_result:
            return send_result['result']
        raise ValueError("Failed to send transaction.")

    def estimate_gas(self, from_address: str, to_address: str, amount: float) -> int:
        params = [{
            'from': to_checksum_address(from_address),
            'to': to_checksum_address(to_address),
            'value': hex(int(amount * 10**18))
        }]
        result = self._make_rpc_call("eth_estimateGas", params)
        if 'result' in result and result['result'] is not None:
            return int(result['result'], 16)
        return 21000

# ==================== WEB3 WALLET WITH PERSISTENCE ====================

class Web3Wallet:
    
    def __init__(self, username: str, password: str, network: str = 'sepolia', private_key: Optional[str] = None, load_existing: bool = False):
        self.username = username
        self.password = password
        self.network = network
        self.blockchain = BlockchainManager(network)
        self.assets = {}
        self.last_update = 0
        
        # Try to load existing wallet if requested
        if load_existing:
            loaded_wallet = WalletStorage.load_wallet(username, password)
            if loaded_wallet:
                self.wallet_data = loaded_wallet
                print(f"✅ Loaded existing wallet: {self.wallet_data['address'][:10]}...")
            else:
                raise ValueError("Failed to load wallet - wrong password or wallet doesn't exist")
        else:
            # Create or import new wallet
            self.wallet_data = self.initialize_wallet(private_key)
            # Save immediately
            WalletStorage.save_wallet(username, password, self.wallet_data)
        
        self.account = Account.from_key(self.wallet_data['private_key'])
        self.credential_manager = CredentialManager(self)

    def create_wallet(self) -> Dict:
        combined = f"{self.username}:{self.password}"
        private_key_int = int.from_bytes(hashlib.sha256(combined.encode()).digest(), 'big') % (2**256)
        if private_key_int == 0:
            private_key_int = 1
        account = Account.from_key(private_key_int)
        return self._create_wallet_dict(account)

    def import_wallet(self, private_key: str) -> Dict:
        try:
            account = Account.from_key(private_key)
            return self._create_wallet_dict(account)
        except (ValueError, binascii.Error) as e:
            raise ValueError(f"Invalid private key format: {e}")

    def _create_wallet_dict(self, account: Account) -> Dict:
        return {
            'private_key': account.key,
            'address': account.address,
            'username': self.username,
            'network': self.network,
            'created_at': int(time.time())
        }

    def initialize_wallet(self, private_key: Optional[str] = None) -> Dict:
        if private_key:
            return self.import_wallet(private_key)
        else:
            return self.create_wallet()
    
    def update_wallet_storage(self):
        """Update the saved wallet file"""
        WalletStorage.save_wallet(self.username, self.password, self.wallet_data)

    def sign_message(self, message: str) -> str:
        message_hash = encode_defunct(text=message)
        signed_message = self.account.sign_message(message_hash)
        return signed_message.signature.hex()

    def update_assets(self, force: bool = False):
        if not force and time.time() - self.last_update < 30:
            return
        print("\nUpdating assets...")
        try:
            balance = self.blockchain.get_balance(self.wallet_data['address'])
            self.assets[self.blockchain.native_asset] = balance
            self.last_update = time.time()
            print("Assets updated successfully.")
        except (ValueError, ConnectionError) as e:
            print(f"Error updating assets: {e}")

    def send_assets(self, to_address: str, amount: float):
        if not to_address.startswith('0x') or len(to_address) != 42:
            print("Error: Invalid recipient address format.")
            return
        if amount <= 0:
            print("Error: Amount must be greater than 0.")
            return
        self.update_assets(force=True)
        time.sleep(1)
        if self.assets.get(self.blockchain.native_asset, 0) < amount:
            print("Error: Insufficient balance.")
            return
        try:
            print(f"\nSending {amount} {self.blockchain.native_asset} to {to_address}...")
            gas = self.blockchain.estimate_gas(self.wallet_data['address'], to_address, amount)
            tx_hash = self.blockchain.send_transaction(self.wallet_data['private_key'], to_address, amount, gas)
            print(f"Transaction sent! TX Hash: {tx_hash}")
            print(f"\nTransaction completed!")
            self.update_assets(force=True)
        except (ValueError, ConnectionError) as e:
            print(f"\nTransaction failed: {e}")

    def display_wallet_info(self):
        print("\n--- Wallet Information ---")
        print(f"Username: {self.wallet_data['username']}")
        print(f"Network:  {self.wallet_data['network']}")
        print(f"Address:  {self.wallet_data['address']}")
        
        if 'created_at' in self.wallet_data:
            created_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.wallet_data['created_at']))
            print(f"Created:  {created_time}")
        
        print("\n--- Assets ---")
        for asset, balance in self.assets.items():
            print(f"{asset}: {balance:.8f}")
        last_update_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.last_update)) if self.last_update else "Never"
        print(f"\n(Last update: {last_update_str})")
        print(f"\n💾 Wallet persisted on disk (encrypted)")

    def blockchain_menu(self):
        while True:
            print("\n" + "="*50)
            print("         BLOCKCHAIN WALLET MENU")
            print("="*50)
            print("1. View Wallet Info")
            print("2. Update Assets")
            print("3. Send Assets")
            print("4. Sign Message")
            print("5. Export Private Key (Caution!)")
            print("6. Delete Wallet (Permanent!)")
            print("7. Back to Main Menu")
            print("="*50)
            choice = input("Enter your choice: ")
            
            if choice == '1':
                self.display_wallet_info()
            elif choice == '2':
                self.update_assets(force=True)
                self.display_wallet_info()
            elif choice == '3':
                try:
                    to_address = input("Enter recipient address: ")
                    amount = float(input("Enter amount to send: "))
                    self.send_assets(to_address, amount)
                except ValueError:
                    print("Invalid amount entered.")
            elif choice == '4':
                message = input("Enter message to sign: ")
                signature = self.sign_message(message)
                print(f"\nSignature: {signature}")
            elif choice == '5':
                print("\n!!! WARNING: Never share your private key !!!")
                if input("Type 'SHOW' to reveal: ") == 'SHOW':
                    print(f"\nPrivate Key: {self.wallet_data['private_key'].hex()}")
                else:
                    print("Display cancelled.")
            elif choice == '6':
                print("\n⚠️  WARNING: This will permanently delete your wallet!")
                print("Make sure you have backed up your private key!")
                confirm = input("Type 'DELETE' to confirm: ")
                if confirm == 'DELETE':
                    if WalletStorage.delete_wallet(self.username, self.password):
                        print("Wallet deleted. Exiting...")
                        return
            elif choice == '7':
                break
            else:
                print("Invalid choice.")

# ==================== CREDENTIAL MENU ====================

def student_wallet_menu(username, blockchain_wallet):
    if not blockchain_wallet:
        print("❌ Blockchain wallet required.")
        return
    
    cred_manager = blockchain_wallet.credential_manager
    
    while True:
        print("\n" + "="*50)
        print("     DECENTRALIZED CREDENTIAL MENU")
        print("="*50)
        print("1. View My Credential (From Blockchain)")
        print("2. Back to Main Menu")
        print("="*50)
        choice = input("> ")

        if choice == '1':
            print("\n👁️  Retrieving credential from blockchain...")
            cred_hash = cred_manager.get_credential_from_chain()
            
            if cred_hash:
                print(f"\n✅ Credential found!")
                print(f"📜 Hash: {cred_hash}")
                print(f"📍 Address: {blockchain_wallet.wallet_data['address']}")
            else:
                print("\n❌ No credential found.")
        
        elif choice == '2':
            break

# ==================== FACE FUNCTIONS ====================

def load_face_data() -> Dict:
    if os.path.exists(FACE_DATA_FILE):
        try:
            with open(FACE_DATA_FILE, 'rb') as f:
                encrypted_data = f.read()
            decrypted = FaceDataEncryption.decrypt_data(encrypted_data)
            return {user: np.array(embed) for user, embed in decrypted.items()}
        except Exception as e:
            print(f"⚠️  Error loading face data: {e}")
            return {}
    return {}

def save_face_data(face_data: Dict):
    try:
        serializable = {}
        for user, embed in face_data.items():
            if isinstance(embed, np.ndarray):
                serializable[user] = embed.tolist()
            else:
                serializable[user] = embed
        
        encrypted_data = FaceDataEncryption.encrypt_data(serializable)
        with open(FACE_DATA_FILE, 'wb') as f:
            f.write(encrypted_data)
        print("🔒 Face data encrypted and saved.")
    except Exception as e:
        print(f"⚠️  Error saving face data: {e}")

def capture_face_embedding_with_liveness() -> Optional[np.ndarray]:
    print("\n📸 Starting face capture...")
    
    action = LivenessDetector.request_random_action()
    action_text = {
        "blink": "Please BLINK your eyes",
        "turn_left": "Please turn your head LEFT",
        "turn_right": "Please turn your head RIGHT"
    }
    
    print(f"🎯 Liveness Check: {action_text.get(action, action)}")
    print("You have 15 seconds...")
    
    video_capture = cv2.VideoCapture(0)
    start_time = time.time()
    timeout = 15
    captured_frames = []
    embedding = None

    while time.time() - start_time < timeout:
        ret, frame = video_capture.read()
        if not ret:
            continue

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        display_frame = frame.copy()
        cv2.putText(display_frame, action_text.get(action, action), 
                   (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
        
        remaining = int(timeout - (time.time() - start_time))
        cv2.putText(display_frame, f"Time: {remaining}s", 
                   (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        
        if face_encodings:
            captured_frames.append(frame.copy())
            cv2.putText(display_frame, "Face detected", 
                       (10, 90), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
            embedding = face_encodings[0]
        
        cv2.imshow('Liveness Detection', display_frame)
        
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    video_capture.release()
    cv2.destroyAllWindows()
    
    if len(captured_frames) > 0:
        print("🔍 Verifying liveness...")
        action_completed = LivenessDetector.verify_action(action, captured_frames)
        
        if action_completed:
            print("✅ Liveness check passed!")
            return embedding
        else:
            print("❌ Liveness check failed.")
            return None
    else:
        print("❌ No face captured.")
        return None

def is_face_duplicate(new_embedding, existing_data, tolerance=0.45) -> Tuple[bool, Optional[str]]:
    if len(existing_data) == 0:
        return False, None

    known_embeddings = list(existing_data.values())
    results = face_recognition.compare_faces(known_embeddings, new_embedding, tolerance=tolerance)
    
    if any(results):
        matched_user = list(existing_data.keys())[results.index(True)]
        return True, matched_user
    return False, None

def register_face_for_user(username: str) -> bool:
    face_data = load_face_data()
    
    # Check if already registered
    if username in face_data:
        print(f"✅ Face already registered for '{username}'.")
        return True
    
    print("\n🔐 Face Registration")
    print("=" * 50)
    
    embedding = capture_face_embedding_with_liveness()
    
    if embedding is None:
        print("❌ Face capture failed.")
        return False
    
    is_duplicate, matched_user = is_face_duplicate(embedding, face_data, tolerance=0.45)
    
    if is_duplicate:
        print(f"⚠️  Face already registered to: {matched_user}")
        print("❌ Cannot use same face for multiple accounts.")
        return False
    
    face_data[username] = embedding
    save_face_data(face_data)
    
    loaded_data = load_face_data()
    if username in loaded_data:
        print(f"✅ Face registered for '{username}'.")
        return True
    else:
        print("❌ Registration failed.")
        return False

def verify_user_face(username: str, max_attempts: int = 3) -> bool:
    face_data = load_face_data()
    
    if username not in face_data:
        print(f"❌ No face registered for '{username}'.")
        return False
    
    known_embedding = face_data[username]
    
    for attempt in range(max_attempts):
        print(f"\n🔐 Face Verification (Attempt {attempt + 1}/{max_attempts})")
        print("=" * 50)
        
        action = LivenessDetector.request_random_action()
        action_text = {
            "blink": "Please BLINK",
            "turn_left": "Turn head LEFT",
            "turn_right": "Turn head RIGHT"
        }
        
        print(f"🎯 {action_text.get(action, action)}")
        
        video_capture = cv2.VideoCapture(0)
        verified = False
        liveness_passed = False
        start_time = time.time()
        timeout = 15
        captured_frames = []
        
        while time.time() - start_time < timeout:
            ret, frame = video_capture.read()
            if not ret:
                continue
                
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            face_locations = face_recognition.face_locations(rgb_frame)
            face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

            display_frame = frame.copy()
            cv2.putText(display_frame, action_text.get(action, action), 
                       (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            
            remaining = int(timeout - (time.time() - start_time))
            cv2.putText(display_frame, f"Time: {remaining}s - Q to cancel", 
                       (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
            
            cv2.imshow('Face Verification', display_frame)

            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

            if face_encodings:
                captured_frames.append(frame.copy())
                
                result = face_recognition.compare_faces(
                    [known_embedding], 
                    face_encodings[0], 
                    tolerance=0.45
                )
                
                if result[0]:
                    if len(captured_frames) >= 5:
                        liveness_passed = LivenessDetector.verify_action(action, captured_frames)
                        if liveness_passed:
                            verified = True
                            break

        video_capture.release()
        cv2.destroyAllWindows()

        if verified and liveness_passed:
            print("\n✅ Verification successful!")
            return True
        else:
            print("\n❌ Verification failed.")
        
        if attempt < max_attempts - 1:
            print("Try again...")
    
    return False

# ==================== MAIN ====================

def main():
    
    username = input("\nEnter your username: ")
    password = getpass.getpass("Enter your password: ")

    blockchain_wallet = None

    try:
        # Check if wallet already exists
        if WalletStorage.wallet_exists(username):
            print("\n🔍 Existing wallet found!")
            choice = input("1. Load existing wallet\n2. Create new wallet (overwrites old)\nChoose: ")
            
            if choice == '1':
                # Load existing wallet
                try:
                    network = input("Network (mainnet/sepolia) [sepolia]: ").lower() or 'sepolia'
                    if network not in NETWORKS:
                        print("Invalid network. Using sepolia.")
                        network = 'sepolia'
                    
                    blockchain_wallet = Web3Wallet(username, password, network, load_existing=True)
                    
                    # Check if face is registered
                    face_data = load_face_data()
                    if username not in face_data:
                        print("\n⚠️  Face not registered for this wallet.")
                        print("🔐 Face registration required.")
                        if not register_face_for_user(username):
                            print("\n❌ Cannot proceed without face registration.")
                            return
                    else:
                        print("✅ Face data found.")
                        
                except ValueError as e:
                    print(f"\n❌ {e}")
                    return
            else:
                # Create new wallet
                print("\n⚠️  This will overwrite the existing wallet!")
                confirm = input("Type 'OVERWRITE' to continue: ")
                if confirm != 'OVERWRITE':
                    print("Cancelled.")
                    return
        
        # Create new wallet if not loaded
        if blockchain_wallet is None:
            startup_choice = input(
                "\n1. Create New Wallet\n"
                "2. Import Existing Wallet\n"
                "Choose: "
            )
            
            if startup_choice == '1':
                network = input("Network (mainnet/sepolia) [sepolia]: ").lower() or 'sepolia'
                if network not in NETWORKS:
                    print("Invalid network. Using sepolia.")
                    network = 'sepolia'
                blockchain_wallet = Web3Wallet(username, password, network)
                print("\n✅ Wallet created and saved.")

                print("\n🔐 Face Registration Required")
                if not register_face_for_user(username):
                    print("\n❌ Cannot proceed without face registration.")
                    return
                    
            elif startup_choice == '2':
                private_key = getpass.getpass("Enter private key: ").strip()
                network = input("Network (mainnet/sepolia) [sepolia]: ").lower() or 'sepolia'
                if network not in NETWORKS:
                    print("Invalid network. Using sepolia.")
                    network = 'sepolia'
                blockchain_wallet = Web3Wallet(username, password, network, private_key)
                print("\n✅ Wallet imported and saved.")

                print("\n🔐 Face Registration Required")
                if not register_face_for_user(username):
                    print("\n❌ Cannot proceed without face registration.")
                    return
            else:
                print("Invalid choice.")
                return
            
    except (ValueError, ConnectionError) as e:
        print(f"\n❌ Initialization failed: {e}")
        return

    # Main menu
    while True:
        print("\n" + "="*40)
        print("        MAIN MENU")
        print("="*40)
        print("1. 📜 Credentials (On-Chain)")
        if blockchain_wallet:
            print("2. ⛓️  Blockchain Wallet")
        print("3. 🚪 Exit")
        print("="*40)
        choice = input("Choice: ")

        if choice == '1':
            print("\n🔐 Face verification required...")
            if not verify_user_face(username):
                print("\n❌ Access denied.")
                continue
            
            student_wallet_menu(username, blockchain_wallet)
            
        elif choice == '2' and blockchain_wallet:
            print("\n🔐 Face verification required...")
            if not verify_user_face(username):
                print("\n❌ Access denied.")
                continue
            
            blockchain_wallet.blockchain_menu()
            
        elif choice == '3':
            print("\n" + "="*40)
            print("👋 Thank you!")
            print("🔒 Your wallet is safely encrypted on disk.")
            print("💾 You can access it anytime with your password.")
            print("="*40)
            break
        else:
            print("\n❌ Invalid choice.")

if __name__ == "__main__":
    main()