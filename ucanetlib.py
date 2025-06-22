import re
import tldextract
import time
import git
import os
from apscheduler.schedulers.background import BackgroundScheduler
from ipaddress import ip_address, IPv4Address
from cachetools import TTLCache
from threading import Lock

# === Configuration ===

REGISTRY_PATH = "./ucanet-registry/ucanet-registry.txt"
GIT_USERNAME = "YOUR_USERNAME" # Not required. Only needed if running the Discord bot
GIT_PASSWORD = "YOUR_TOKEN" # Not required. Only needed if running the Discord bot
GIT_URL = f'https://{GIT_USERNAME}:{GIT_PASSWORD}@github.com/ucanet/ucanet-registry.git'
GIT_BRANCH = "main"
GIT_PATH = "./ucanet-registry/"
CACHE_SIZE = 3500
CACHE_TTL = 600

# === Global State ===

origin = repo = None # Will store the origin and repository for pulling content
pending_changes = {}  # Temporary changes not yet committed
entry_cache = TTLCache(maxsize=CACHE_SIZE, ttl=CACHE_TTL) # Domain cache
offline_extract = tldextract.TLDExtract(suffix_list_urls=()) # No external TLD list fetching
git_scheduler = BackgroundScheduler()

# Locks for thread-safe access
entry_lock = Lock()
file_lock = Lock()
pending_lock = Lock()
	
# === Git Handling ===

def is_git_repo(path):
	"""Check if a directory is a valid Git repo."""
	try:
		_ = git.Repo(path).git_dir
		return True
	except git.exc.InvalidGitRepositoryError:
		return False

def start_git():
	"""Initialize or connect to remote Git repo."""
	if is_git_repo(GIT_PATH):	
		repo = git.Repo.init(GIT_PATH, initial_branch=GIT_BRANCH)	
		return repo, repo.remote(name='origin')
	else:	
		repo = git.Repo.init(GIT_PATH, initial_branch=GIT_BRANCH)	
		return repo, repo.create_remote('origin', GIT_URL)

def pull_git():
	"""Safely pull latest changes from the remote registry repo."""
	with file_lock:
		try:
			origin.pull(GIT_BRANCH)
		except:
			pass
	
def push_git():
	"""Push all pending domain changes to the registry repo."""
	with pending_lock, file_lock:
		if len(pending_changes) > 0:
			try:
				formatted_changes = {}
				# Reformat pending changes to registry line format
				for user_id, domain_list in pending_changes.items():
					for current_name, current_ip in domain_list.items():
						formatted_changes[current_name] = f'{current_name} {user_id} {current_ip}' + "\n"
				
				# Read existing registry line entries
				with open(REGISTRY_PATH, 'r') as registry_file:
					registry_lines = registry_file.readlines()
					
				# Overwrite existing entries
				line_count = 0
				for line in registry_lines:
					split_lines = line.strip().split(' ')			
					if split_lines[0] in formatted_changes:
						registry_lines[line_count] = formatted_changes[split_lines[0]]
						del formatted_changes[split_lines[0]]					
					line_count += 1
				
				# Append any new domains
				for current_name, formatted_change in formatted_changes.items():
					if len(registry_lines) > 0:
						registry_lines[-1] = registry_lines[-1].replace("\n", "")
						registry_lines[-1] = registry_lines[-1] + "\n"
					registry_lines.append(formatted_change)
				
				if len(registry_lines) > 0:
					registry_lines[-1] = registry_lines[-1].replace("\n", "")
					
				with open(REGISTRY_PATH, 'w') as registry_file:
					registry_file.writelines(registry_lines)
					
				pending_changes.clear()
			except:
				pass
			
			try:
				repo = git.Repo(GIT_PATH)
				repo.git.add(all=True)
				repo.index.commit("[automated] update registry")
				repo.git.push('--set-upstream', repo.remote().name, GIT_BRANCH)
			except:
				pass

def schedule_git():
	"""Schedule Git pull and push tasks."""
	git_scheduler.add_job(id='git-pull-task', func=pull_git, trigger='interval', seconds=600)
	git_scheduler.add_job(id='git-push-task', func=push_git, trigger='interval', seconds=15)
	git_scheduler.start()
    
# === Domain + IP Formatting ===

def format_domain(domain_name):
	"""Validate and normalize domain format."""
	domain_name = domain_name.lower()
	if len(domain_name) > 255:
		return False
	if domain_name[-1] == ".":
		domain_name = domain_name[:-1]
	allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	if all(allowed.match(x) for x in domain_name.split(".")):
		extracted = offline_extract(domain_name)
		if len(extracted.domain) > 0 and len(extracted.suffix) > 0:
			return domain_name
	return False

def format_ip(current_ip):
	"""Validate or convert IP (or placeholder)."""
	if current_ip == "none":
		return "0.0.0.0"
	try:
		return current_ip if type(ip_address(current_ip)) is IPv4Address else False
	except ValueError:
		return False

def second_level(domain_name):
	"""Return second-level fallback for subdomains (e.g. sub.site.com → site.com)."""
	domain_name = format_domain(domain_name)	
	if domain_name:
		extracted = offline_extract(domain_name)	
		if len(extracted.subdomain) > 0:
			return "{}.{}".format(extracted.domain, extracted.suffix)		
	return False

# === Lookup Functions ===

def find_pending(domain_name):
	"""Check if a domain is in the pending_changes buffer."""
	with pending_lock:
		for user_id, domain_list in pending_changes.items():
			for current_name, current_ip in domain_list.items():
				if current_name == domain_name:
					return current_ip
	return False
	
def find_entry(domain_name):
	"""Find the IP for a given domain from pending cache, memory cache, or file."""
	if not domain_name:
		return False
		
	domain_name = format_domain(domain_name)
	if found_pending := find_pending(domain_name):
		return found_pending
	
	with entry_lock:
		if domain_name in entry_cache.keys():
			return entry_cache[domain_name]
		
	if domain_name:
		with file_lock, open(REGISTRY_PATH, 'r') as registry_file:
				registry_lines = registry_file.readlines()
		
		for line in registry_lines:
			split_lines = line.strip().split(' ')
			if split_lines[0] == domain_name:
				with entry_lock:
					entry_cache[domain_name] = split_lines[2]
				return split_lines[2]
						
		# Handle second-level subdomains
		if entry := find_entry(second_level(domain_name)):
			with entry_lock:
				entry_cache[domain_name] = entry
			return entry
			
	return False

# === User Management ===

def user_domains(user_id):
	"""Return all domains registered by a user."""
	domain_list = {}

	with file_lock, open(REGISTRY_PATH, 'r') as registry_file:
		registry_lines = registry_file.readlines()
	
	for line in registry_lines:
		split_lines = line.strip().split(' ')
		if int(split_lines[1]) == user_id:
			domain_list[split_lines[0]] = split_lines[2]
			
	# Merge in pending changes
	with pending_lock:
		if user_id in pending_changes.keys():
			for domain_name, current_ip in pending_changes[user_id].items():
				domain_list[domain_name] = current_ip

	return domain_list
	
def register_domain(domain_name, user_id):
	"""Register a new domain for a user with placeholder IP."""
	domain_list = user_domains(user_id)
	if len(domain_list) >= 20:
		return False
	with pending_lock:
		if user_id not in pending_changes.keys():
			pending_changes[user_id] = {}
		pending_changes[user_id][domain_name] = "0.0.0.0"
	print(f'{domain_name} registered by {user_id}')
	return True
	
def register_ip(domain_name, user_id, current_ip):
	"""Register or update the IP for a domain."""
	domain_list = user_domains(user_id)
	if len(domain_list) >= 20 and domain_name not in domain_list:
		return False
	with pending_lock:
		if user_id not in pending_changes.keys():
			pending_changes[user_id] = {}
		pending_changes[user_id][domain_name] = current_ip
	print(f'{domain_name} set ip to {current_ip} by {user_id}')
	return True

# === Startup Tasks ===

def init_library():
	"""Initialize the Git repository environment and start syncing."""
	global repo, origin

	# Ensure Registry path exists
	if not os.path.exists(GIT_PATH):
		os.makedirs(GIT_PATH)
		
	# Set initial repo to start with
	repo, origin = start_git()
	repo.git.add(all=True)

	# Start the repository syncing
	pull_git()
	schedule_git()