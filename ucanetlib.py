import re
import tldextract
import time
import git
from apscheduler.schedulers.background import BackgroundScheduler
from ipaddress import ip_address, IPv4Address
from cachetools import TTLCache
from threading import Lock

REGISTRY_PATH = "ucanet-registry.txt"
GIT_USERNAME = "YOUR_USERNAME" # Not required. Only needed if running the Discord bot
GIT_PASSWORD = "YOUR_TOKEN" # Not required. Only needed if running the Discord bot
GIT_URL = f'https://{GIT_USERNAME}:{GIT_PASSWORD}@github.com/ucanet/ucanet-registry.git'
GIT_BRANCH = "main"
GIT_PATH = "."
CACHE_SIZE = 3500
CACHE_TTL = 600

pending_changes = {}
entry_cache = TTLCache(maxsize=CACHE_SIZE, ttl=CACHE_TTL)
offline_extract = tldextract.TLDExtract(suffix_list_urls=())
git_scheduler = BackgroundScheduler()
entry_lock = Lock()
file_lock = Lock()
pending_lock = Lock()

def is_git_repo(path):
    try:
        _ = git.Repo(path).git_dir
        return True
    except git.exc.InvalidGitRepositoryError:
        return False

def start_git():
	if is_git_repo(GIT_PATH):	
		repo = git.Repo.init(GIT_PATH, initial_branch=GIT_BRANCH)	
		return repo, repo.remote(name='origin')
	else:	
		repo = git.Repo.init(GIT_PATH, initial_branch=GIT_BRANCH)	
		return repo, repo.create_remote('origin', GIT_URL)
		
repo, origin = start_git()
repo.git.add(all=True)

def pull_git():
	file_lock.acquire()
	try:
		origin.pull(GIT_BRANCH)
	except:
		pass
	file_lock.release()
	
def push_git():
	pending_lock.acquire()
	file_lock.acquire()
	if len(pending_changes) > 0:
		try:
			formatted_changes = {}
			
			for user_id, domain_list in pending_changes.items():
				for current_name, current_ip in domain_list.items():
					formatted_changes[current_name] = f'{current_name} {user_id} {current_ip}' + "\n"
			
			with open(REGISTRY_PATH, 'r') as registry_file:
				registry_lines = registry_file.readlines()
				
			line_count = 0
			
			for line in registry_lines:
				split_lines = line.strip().split(' ')
				
				if split_lines[0] in formatted_changes:
					registry_lines[line_count] = formatted_changes[split_lines[0]]
					del formatted_changes[split_lines[0]]
					
				line_count += 1
			
			for current_name, formatted_change in formatted_changes.items():
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
			repo.git.add(REGISTRY_PATH)
			repo.index.commit("[automated] update registry")
			repo.git.push('--set-upstream', repo.remote().name, GIT_BRANCH)
		except:
			pass
			
	file_lock.release()
	pending_lock.release()

def schedule_git():
	git_scheduler.add_job(id='git-pull-task', func=pull_git, trigger='interval', seconds=600)
	git_scheduler.add_job(id='git-push-task', func=push_git, trigger='interval', seconds=15)
	git_scheduler.start()
    
def format_domain(domain_name):
	domain_name = domain_name.lower()
	if len(domain_name) > 255:
		return False
	if domain_name[-1] == ".":
		domain_name = domain_name[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	if all(allowed.match(x) for x in domain_name.split(".")):
		extracted = offline_extract(domain_name)
		if len(extracted.domain) > 0 and len(extracted.suffix) > 0:
			return domain_name
	return False

def format_ip(current_ip):
	if current_ip == "none":
		return "0.0.0.0"
	try:
		return current_ip if type(ip_address(current_ip)) is IPv4Address else False
	except ValueError:
		return False

def second_level(domain_name):
	domain_name = format_domain(domain_name)
	
	if domain_name:
		extracted = offline_extract(domain_name)
		
		if len(extracted.subdomain) > 0:
			return "{}.{}".format(extracted.domain, extracted.suffix)
		
	return False

def find_pending(domain_name):
	pending_lock.acquire()
	for user_id, domain_list in pending_changes.items():
		for current_name, current_ip in domain_list.items():
			if current_name == domain_name:
				pending_lock.release()
				return current_ip
	pending_lock.release()
	return False
	
def find_entry(domain_name):
	if not domain_name:
		return False
		
	domain_name = format_domain(domain_name)
	if found_pending := find_pending(domain_name):
		return found_pending
	
	entry_lock.acquire()
	if domain_name in entry_cache.keys():
		entry_lock.release()
		return entry_cache[domain_name]
	entry_lock.release()
		
	if domain_name:
		file_lock.acquire()
		registry_file = open(REGISTRY_PATH, 'r')
		registry_lines = registry_file.readlines()
		registry_file.close()
		file_lock.release()
		
		for line in registry_lines:
			split_lines = line.strip().split(' ')
			if split_lines[0] == domain_name:
				entry_lock.acquire()
				entry_cache[domain_name] = split_lines[2]
				entry_lock.release()
				return split_lines[2]
						
		if entry := find_entry(second_level(domain_name)):
			entry_lock.acquire()
			entry_cache[domain_name] = entry
			entry_lock.release()
			return entry
			
	return False
	
def user_domains(user_id):
	domain_list = {}

	file_lock.acquire()
	registry_file = open(REGISTRY_PATH, 'r')
	registry_lines = registry_file.readlines()
	registry_file.close()
	file_lock.release()
	
	for line in registry_lines:
		split_lines = line.strip().split(' ')
		if int(split_lines[1]) == user_id:
			domain_list[split_lines[0]] = split_lines[2]
			
	pending_lock.acquire()
	if user_id in pending_changes.keys():
		for domain_name, current_ip in pending_changes[user_id].items():
			domain_list[domain_name] = current_ip
	pending_lock.release()

	return domain_list
	
def register_domain(domain_name, user_id):
	domain_list = user_domains(user_id)
	if len(domain_list) >= 20:
		return False
	pending_lock.acquire()
	if user_id not in pending_changes.keys():
		pending_changes[user_id] = {}
	pending_changes[user_id][domain_name] = "0.0.0.0"
	pending_lock.release()
	print(f'{domain_name} registered by {user_id}')
	return True
	
def register_ip(domain_name, user_id, current_ip):
	domain_list = user_domains(user_id)
	if len(domain_list) >= 20 and domain_name not in domain_list:
		return False
	pending_lock.acquire()
	if user_id not in pending_changes.keys():
		pending_changes[user_id] = {}
	pending_changes[user_id][domain_name] = current_ip
	pending_lock.release()
	print(f'{domain_name} set ip to {current_ip} by {user_id}')
	return True
	
pull_git()
schedule_git()
