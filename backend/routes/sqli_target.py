"""Controlled Demo Target Web Application for SQL Injection Defense Lab.

Provides a realistic, clean e-commerce product catalog web application
at /lab/sqli-target and /lab/sqli-target/search.

This target application represents an innocent enterprise/store service:
- Normal catalog browsing and search UI
- Clean product search by name, category, or description
- NO attack buttons, NO SQLi buttons, NO presets
- NO "attack detected" or security vendor hardcoding
- Thread-safe invocation counter to verify that blocked requests never reach the target
"""

from __future__ import annotations

import html
import threading
from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter(prefix="/lab/sqli-target", tags=["SQLi Demo Target"])

# -----------------------------------------------------------------------------
# Thread-safe Invocation Tracking
# Used to prove that blocked requests are intercepted at the gateway
# and NEVER reach this target application.
# -----------------------------------------------------------------------------
_counter_lock = threading.Lock()
_TARGET_INVOCATION_COUNTER = 0


def get_sqli_target_invocation_count() -> int:
    """Return the total number of times the target search endpoint was reached."""
    with _counter_lock:
        return _TARGET_INVOCATION_COUNTER


def reset_sqli_target_invocation_count() -> None:
    """Reset the target invocation counter to zero."""
    global _TARGET_INVOCATION_COUNTER
    with _counter_lock:
        _TARGET_INVOCATION_COUNTER = 0


def _increment_target_invocation() -> int:
    """Atomically increment and return the target invocation counter."""
    global _TARGET_INVOCATION_COUNTER
    with _counter_lock:
        _TARGET_INVOCATION_COUNTER += 1
        return _TARGET_INVOCATION_COUNTER


# -----------------------------------------------------------------------------
# Realistic Product Catalog Data
# -----------------------------------------------------------------------------
CATALOG_PRODUCTS = [
    {
        "id": 101,
        "name": "UltraBook Pro 15",
        "category": "Laptops",
        "price": "$1,299.00",
        "badge": "Best Seller",
        "description": "High-performance enterprise laptop featuring 32GB LPDDR5, 1TB NVMe SSD, and 14-core processor.",
    },
    {
        "id": 102,
        "name": "ProWireless Precision Mouse",
        "category": "Accessories",
        "price": "$79.99",
        "badge": "Popular",
        "description": "Ergonomic wireless mouse with customizable 16,000 DPI optical sensor and dual-device Bluetooth.",
    },
    {
        "id": 103,
        "name": "MechKey Studio 87",
        "category": "Peripherals",
        "price": "$149.50",
        "badge": "Top Rated",
        "description": "Hot-swappable tenkeyless mechanical keyboard with pre-lubed silent switches and aluminum top plate.",
    },
    {
        "id": 104,
        "name": "VisionPro 27-Inch 4K Display",
        "category": "Monitors",
        "price": "$489.00",
        "badge": "4K UHD",
        "description": "Factory-calibrated IPS monitor with 99% sRGB color accuracy and 90W USB-C Power Delivery.",
    },
    {
        "id": 105,
        "name": "AcousticShield ANC Wireless",
        "category": "Audio",
        "price": "$249.00",
        "badge": "Noise Cancelling",
        "description": "Over-ear studio reference headphones with hybrid active noise cancellation and 40h battery.",
    },
    {
        "id": 106,
        "name": "ThunderDock 12-in-1 Hub",
        "category": "Accessories",
        "price": "$189.00",
        "badge": "Thunderbolt 4",
        "description": "Universal docking station with dual 4K 60Hz display outputs, Gigabit LAN, and SD Express slot.",
    },
]


def _filter_catalog(query: str) -> list[dict[str, Any]]:
    """Filter products by search query across name, category, and description."""
    q = (query or "").strip().lower()
    if not q:
        return CATALOG_PRODUCTS
    return [
        p
        for p in CATALOG_PRODUCTS
        if q in p["name"].lower() or q in p["category"].lower() or q in p["description"].lower()
    ]


def _render_catalog_html(query: str = "", products: Optional[list[dict[str, Any]]] = None) -> str:
    """Render a clean, authentic e-commerce store catalog UI with search bar."""
    items = products if products is not None else CATALOG_PRODUCTS
    escaped_query = html.escape(query or "")

    product_cards_html = ""
    if items:
        for p in items:
            product_cards_html += f"""
            <div class="product-card">
                <div class="product-badge">{html.escape(p.get('badge', 'In Stock'))}</div>
                <div class="product-category">{html.escape(p['category'])}</div>
                <h3 class="product-title">{html.escape(p['name'])}</h3>
                <p class="product-desc">{html.escape(p['description'])}</p>
                <div class="product-footer">
                    <span class="product-price">{html.escape(p['price'])}</span>
                    <button class="btn-buy" type="button">Add to Cart</button>
                </div>
            </div>
            """
    else:
        product_cards_html = f"""
        <div class="no-results">
            <h3>No products found</h3>
            <p>No catalog items matched your search query: <code>{escaped_query}</code></p>
            <a href="/lab/sqli-target" class="btn-reset">View All Products</a>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechGear Electronics — Product Catalog</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --accent: #38bdf8;
            --badge-bg: #0284c7;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}
        header {{
            background-color: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.3rem;
            font-weight: 700;
            color: var(--text-main);
            text-decoration: none;
        }}
        .brand-icon {{
            background: linear-gradient(135deg, #3b82f6, #06b6d4);
            color: white;
            width: 34px;
            height: 34px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
            font-weight: 800;
        }}
        .nav-links {{
            display: flex;
            gap: 20px;
            list-style: none;
        }}
        .nav-links a {{
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.95rem;
            transition: color 0.15s;
        }}
        .nav-links a:hover, .nav-links a.active {{
            color: var(--accent);
        }}
        main {{
            max-width: 1100px;
            width: 100%;
            margin: 0 auto;
            padding: 36px 24px;
            flex: 1;
        }}
        .hero {{
            text-align: center;
            margin-bottom: 32px;
        }}
        .hero h1 {{
            font-size: 2.1rem;
            font-weight: 800;
            margin-bottom: 8px;
            background: linear-gradient(to right, #f8fafc, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .hero p {{
            color: var(--text-muted);
            font-size: 1rem;
        }}
        .search-container {{
            margin: 0 auto 36px auto;
            max-width: 640px;
        }}
        .search-form {{
            display: flex;
            gap: 8px;
            background-color: var(--surface);
            padding: 6px;
            border-radius: 10px;
            border: 1px solid var(--border);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        }}
        .search-input {{
            flex: 1;
            background: transparent;
            border: none;
            padding: 12px 16px;
            font-size: 1rem;
            color: var(--text-main);
            outline: none;
        }}
        .search-input::placeholder {{
            color: var(--text-muted);
        }}
        .search-btn {{
            background-color: var(--primary);
            color: #ffffff;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.15s;
        }}
        .search-btn:hover {{
            background-color: var(--primary-hover);
        }}
        .query-status {{
            margin-bottom: 20px;
            font-size: 0.95rem;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .query-status code {{
            background: var(--surface);
            padding: 2px 6px;
            border-radius: 4px;
            color: var(--accent);
            border: 1px solid var(--border);
        }}
        .catalog-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
            gap: 24px;
        }}
        .product-card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 22px;
            display: flex;
            flex-direction: column;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .product-card:hover {{
            transform: translateY(-3px);
            border-color: #475569;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        }}
        .product-badge {{
            align-self: flex-start;
            background-color: rgba(56, 189, 248, 0.15);
            color: var(--accent);
            font-size: 0.75rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 4px;
            margin-bottom: 12px;
            text-transform: uppercase;
        }}
        .product-category {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .product-title {{
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 10px;
        }}
        .product-desc {{
            font-size: 0.88rem;
            color: var(--text-muted);
            line-height: 1.5;
            flex: 1;
            margin-bottom: 18px;
        }}
        .product-footer {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-top: 14px;
            border-top: 1px solid var(--border);
        }}
        .product-price {{
            font-size: 1.25rem;
            font-weight: 800;
            color: var(--text-main);
        }}
        .btn-buy {{
            background: transparent;
            border: 1px solid var(--primary);
            color: #93c5fd;
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .btn-buy:hover {{
            background-color: var(--primary);
            color: #ffffff;
        }}
        .no-results {{
            grid-column: 1 / -1;
            text-align: center;
            padding: 48px 24px;
            background-color: var(--surface);
            border-radius: 10px;
            border: 1px dashed var(--border);
        }}
        .no-results h3 {{
            font-size: 1.3rem;
            margin-bottom: 10px;
        }}
        .no-results p {{
            color: var(--text-muted);
            margin-bottom: 18px;
        }}
        .btn-reset {{
            display: inline-block;
            background-color: var(--primary);
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 600;
        }}
        footer {{
            text-align: center;
            padding: 24px;
            font-size: 0.85rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            margin-top: auto;
        }}
    </style>
</head>
<body>
    <header>
        <a href="/lab/sqli-target" class="brand">
            <span class="brand-icon">TG</span>
            <span>TechGear Store</span>
        </a>
        <nav>
            <ul class="nav-links">
                <li><a href="/lab/sqli-target" class="active">Catalog</a></li>
                <li><a href="#categories">Categories</a></li>
                <li><a href="#deals">Deals</a></li>
                <li><a href="#support">Support</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <section class="hero">
            <h1>Enterprise Hardware & Peripherals</h1>
            <p>High-reliability workstations, mechanical inputs, and displays for engineering teams</p>
        </section>

        <section class="search-container">
            <form class="search-form" action="/lab/sqli-target/search" method="GET">
                <input
                    type="text"
                    name="q"
                    class="search-input"
                    placeholder="Search catalog (e.g. laptop, monitor, keyboard)..."
                    value="{escaped_query}"
                    autocomplete="off"
                />
                <button type="submit" class="search-btn">Search</button>
            </form>
        </section>

        {"<div class='query-status'><span>Showing results for query: <code>" + escaped_query + "</code> (" + str(len(items)) + " items)</span><a href='/lab/sqli-target' style='color:var(--accent); text-decoration:none;'>Clear filter</a></div>" if query else ""}

        <section class="catalog-grid">
            {product_cards_html}
        </section>
    </main>

    <footer>
        <p>&copy; 2026 TechGear Electronics Inc. All rights reserved.</p>
    </footer>
</body>
</html>
"""


# -----------------------------------------------------------------------------
# Target Endpoints
# -----------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def get_catalog_home():
    """Render the standard e-commerce store catalog homepage."""
    return HTMLResponse(content=_render_catalog_html())


@router.get("/search")
def search_catalog(request: Request, q: str = ""):
    """Execute product catalog search.

    Increments the internal target invocation counter to allow scientific
    verification that blocked requests never reach this handler.
    """
    _increment_target_invocation()
    matching_items = _filter_catalog(q)

    # Check if client asked for JSON (e.g., API consumers / programmatic tests)
    accept_header = request.headers.get("Accept", "").lower()
    if "application/json" in accept_header:
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "query": q,
                "count": len(matching_items),
                "items": matching_items,
            },
        )

    # Browser client: return formatted HTML catalog view
    return HTMLResponse(content=_render_catalog_html(query=q, products=matching_items))


@router.get("/invocation-count")
def get_invocation_count():
    """Diagnostic endpoint to inspect how many times the target was reached."""
    return {"invocation_count": get_sqli_target_invocation_count()}


@router.post("/reset-counter")
def reset_counter():
    """Diagnostic endpoint to reset the target invocation counter."""
    reset_sqli_target_invocation_count()
    return {"status": "reset", "invocation_count": 0}
