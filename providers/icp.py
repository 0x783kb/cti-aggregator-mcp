import time
import uuid
import re
import asyncio
from datetime import datetime
from bs4 import BeautifulSoup
from typing import Dict, Any, List

def _get_mac_string() -> str:
    """
    Generates the 'mac_string' cookie value required by beianx.cn.
    Format: 2-digit day of month + UUID.
    """
    today = datetime.now()
    day_str = str(today.day).zfill(2)
    uid = str(uuid.uuid4())
    return f"{day_str}{uid}"

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    Query ICP filing information from beianx.cn.
    """
    base_url = f"https://www.beianx.cn/search/{domain}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://www.beianx.cn/"
    }

    try:
        # Step 1: Initial request to get 'acw_tc' cookie
        # Note: The site might return 405 or 521 initially, but we need the Set-Cookie header.
        resp1 = await client.get(base_url, headers=headers)
        
        # Extract acw_tc from cookies
        acw_tc = resp1.cookies.get("acw_tc")
        if not acw_tc:
            # Try to see if it's in the history (if redirected)
            for r in resp1.history:
                if "acw_tc" in r.cookies:
                    acw_tc = r.cookies["acw_tc"]
                    break
        
        # If we still don't have it, maybe it wasn't set?Proceed anyway but it might fail.
        
        # Step 2: Construct cookies
        mac_string = _get_mac_string()
        cookies = {
            "mac_string": mac_string
        }
        if acw_tc:
            cookies["acw_tc"] = acw_tc

        # Step 3: Second request with cookies
        # Add a small delay as the JS script does setTimeout(..., 200)
        await asyncio.sleep(0.3)
        
        resp2 = await client.get(base_url, headers=headers, cookies=cookies)
        
        if resp2.status_code != 200:
            return {"error": f"HTTP Error {resp2.status_code}"}

        soup = BeautifulSoup(resp2.text, "html.parser")
        
        # Check for error or no results
        # Look for table
        table = soup.find("table", class_="table")
        if not table:
            # Check for "未查询到" message
            if "未查询到" in resp2.text:
                 return {"results": [], "message": "No ICP filing found"}
            return {"error": "Failed to parse response (Table not found)"}

        results = []
        # Skip header row
        rows = table.find_all("tr")[1:] 
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 7:
                item = {
                    "entity_name": cols[1].get_text(strip=True),
                    "entity_type": cols[2].get_text(strip=True),
                    "license_number": cols[3].get_text(strip=True),
                    "site_name": cols[4].get_text(strip=True),
                    "site_url": cols[5].get_text(strip=True),
                    "audit_date": cols[6].get_text(strip=True)
                }
                results.append(item)

        return {
            "results": results,
            "source": "beianx.cn"
        }

    except Exception as e:
        return {"error": str(e)}
