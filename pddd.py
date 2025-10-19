import os
import re
import sys
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# 🎨 لوجو الأداة
def print_logo():
    print("\033[96m")  # لون سماوي
    print(" █████   █████ ██████████ █████████   ██████   █████ ")
    print("░░███   ░░███ ░░███░░░░░ ░░███░░░░█  ░░██████ ░░███  ")
    print(" ░███    ░███  ░███       ░███  ░ ░   ░███░███ ░███  ")
    print(" ░███████████  ░█████████ ░███        ░███░░███░███  ")
    print(" ░███░░░░░███  ░░░░░░░░███░███   ███  ░███ ░░██████  ")
    print(" ░███    ░███  ███    ░███░███  ░░███ ░███  ░░█████  ")
    print(" █████   █████░░█████████ ██████████  █████  ░░█████ ")
    print("░░░░░   ░░░░░  ░░░░░░░░░ ░░░░░░░░░░  ░░░░░    ░░░░░  ")
    print("           🌐 WebScraper Agent - v1.0")
    print("\033[0m")

print_logo()

# إعداد مجلد الحفظ
output_dir = "./theagent"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

visited = set()
queue = deque()
download_queue = []  # قائمة الملفات المراد تحميلها بالتوازي

# ------------------------
def sanitize_filename(filename, default_ext=".dat"):
    filename = filename.split("?")[0]
    filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
    if not os.path.splitext(filename)[1]:
        filename += default_ext
    return filename

# عداد للـ progress bar
total_files = 0
downloaded_files = 0

def update_progress():
    percent = int(downloaded_files / total_files * 100) if total_files else 100
    bar = "#" * (percent // 2) + "-" * (50 - percent // 2)
    sys.stdout.write(f"\r[{bar}] {percent}%")
    sys.stdout.flush()

def download_file(file_url, default_ext=".dat"):
    global downloaded_files
    try:
        filename = sanitize_filename(os.path.basename(file_url), default_ext)
        path = os.path.join(output_dir, filename)
        if os.path.exists(path):
            downloaded_files += 1
            update_progress()
            return path
        response = requests.get(file_url, timeout=5)
        response.raise_for_status()
        with open(path, "wb") as f:
            f.write(response.content)
        downloaded_files += 1
        update_progress()
        return path
    except Exception:
        downloaded_files += 1
        update_progress()
        return None

# ------------------------
def process_page(page_url, base_domain):
    try:
        response = requests.get(page_url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # حفظ HTML
        filename = sanitize_filename(urlparse(page_url).path.strip("/")) or "index.html"
        if not filename.endswith(".html"):
            filename += ".html"
        html_path = os.path.join(output_dir, filename)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(str(soup))

        # CSS
        css_files = []
        for css in soup.find_all("link", rel="stylesheet"):
            css_url = urljoin(page_url, css.get("href"))
            download_queue.append((css_url, ".css"))
            css_files.append(css_url)

        # JS
        for js in soup.find_all("script", src=True):
            js_url = urljoin(page_url, js.get("src"))
            download_queue.append((js_url, ".js"))

        # الصور
        for img in soup.find_all("img", src=True):
            img_url = urljoin(page_url, img.get("src"))
            download_queue.append((img_url, ".jpg"))

        # صور داخل CSS (background-image)
        css_img_pattern = re.compile(r'url\(["\']?(.*?)["\']?\)')
        for css_url in css_files:
            try:
                response_css = requests.get(css_url, timeout=5)
                response_css.raise_for_status()
                for match in css_img_pattern.findall(response_css.text):
                    if match.startswith("data:"):
                        continue
                    img_url = urljoin(css_url, match)
                    download_queue.append((img_url, ".jpg"))
            except:
                continue

        # روابط الصفحات الداخلية
        for a in soup.find_all("a", href=True):
            link = urljoin(page_url, a["href"])
            if base_domain in link and link not in visited:
                queue.append(link)

    except Exception as e:
        print(f"⚠ Failed to process {page_url}: {e}")

# ------------------------
# البداية
start_url = input("Enter main website URL: ").strip()
base_domain = urlparse(start_url).netloc
queue.append(start_url)

# زحف الصفحات
while queue:
    link = queue.popleft()
    if link in visited:
        continue
    visited.add(link)
    process_page(link, base_domain)

# تنزيل الملفات بالتوازي
total_files = len(download_queue)
downloaded_files = 0
update_progress()  # عرض 0% بداية

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(download_file, url, ext) for url, ext in download_queue]
    for future in as_completed(futures):
        future.result()

# نهاية progress
sys.stdout.write("\n")
print("\n🎉 Crawl finished. Full website saved to", output_dir)
