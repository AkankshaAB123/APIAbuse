import { useState } from "react";
import {
  ShoppingBag,
  Search,
  ShoppingCart,
  User,
  Truck,
  ShieldCheck,
  RotateCcw,
  Headphones as SupportIcon,
  Check,
  Star,
} from "lucide-react";
import { API_BASE_URL } from "../services/api";
import "./DemoShop.css";

const STORE_PRODUCTS = [
  {
    id: 1,
    name: "Enterprise Pro Laptop",
    category: "Computers",
    price: 1200.0,
    icon: "💻",
    rating: 4.9,
    reviews: 128,
  },
  {
    id: 2,
    name: "NextGen Smartphone",
    category: "Mobile",
    price: 800.0,
    icon: "📱",
    rating: 4.8,
    reviews: 95,
  },
  {
    id: 3,
    name: "Wireless ANC Headphones",
    category: "Audio",
    price: 150.0,
    icon: "🎧",
    rating: 4.7,
    reviews: 210,
  },
  {
    id: 4,
    name: "Mechanical Gaming Keyboard",
    category: "Peripherals",
    price: 90.0,
    icon: "⌨️",
    rating: 4.9,
    reviews: 74,
  },
  {
    id: 5,
    name: "Ergonomic Laser Mouse",
    category: "Peripherals",
    price: 45.0,
    icon: "🖱️",
    rating: 4.6,
    reviews: 142,
  },
  {
    id: 6,
    name: "UltraWide 4K Monitor",
    category: "Displays",
    price: 350.0,
    icon: "🖥️",
    rating: 4.9,
    reviews: 88,
  },
];

const CATEGORIES = ["All", "Computers", "Mobile", "Audio", "Peripherals", "Displays"];

export default function DemoShop() {
  const [searchQuery, setSearchQuery] = useState("");
  const [searchLoading, setSearchLoading] = useState(false);
  const [activeSearch, setActiveSearch] = useState(null);
  const [searchResults, setSearchResults] = useState([]);
  const [searchError, setSearchError] = useState(null);

  const [activeCategory, setActiveCategory] = useState("All");
  const [cartCount, setCartCount] = useState(0);
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (message) => {
    setToastMessage(message);
    setTimeout(() => {
      setToastMessage(null);
    }, 3000);
  };

  const handleAddToCart = (productName) => {
    setCartCount((prev) => prev + 1);
    showToast(`Added "${productName}" to your cart.`);
  };

  // Perform GET /lab/products/search?query=...
  const handleSearch = async (overrideTerm) => {
    const term = typeof overrideTerm === "string" ? overrideTerm : searchQuery;
    if (!term.trim()) {
      return;
    }

    setSearchLoading(true);
    setSearchError(null);

    try {
      const encoded = encodeURIComponent(term.trim());
      const response = await fetch(`${API_BASE_URL}/lab/products/search?query=${encoded}`);

      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status}`);
      }

      const data = await response.json();
      const targetRes = data.vulnerable_target_response || {};
      const rows = targetRes.body?.rows || [];

      // Format backend rows into products
      const formattedRows = rows.map((r, index) => ({
        id: r.id || index + 100,
        name: r.name,
        category: r.category ? r.category.charAt(0).toUpperCase() + r.category.slice(1) : "Electronics",
        price: Number(r.price) || 0,
        icon: r.name.toLowerCase().includes("laptop")
          ? "💻"
          : r.name.toLowerCase().includes("phone")
          ? "📱"
          : r.name.toLowerCase().includes("guide") || r.name.toLowerCase().includes("book")
          ? "📚"
          : "📦",
        rating: 4.8,
        reviews: 45,
      }));

      setActiveSearch(term.trim());
      setSearchResults(formattedRows);
    } catch (err) {
      setSearchError("Unable to load search results. Please check your connection.");
    } finally {
      setSearchLoading(false);
    }
  };

  const handleClearSearch = () => {
    setActiveSearch(null);
    setSearchResults([]);
    setSearchQuery("");
    setSearchError(null);
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      handleSearch();
    }
  };

  const handleChipClick = (term) => {
    setSearchQuery(term);
    handleSearch(term);
  };

  // Filter products by category if not actively searching
  const displayedProducts = activeSearch
    ? searchResults
    : activeCategory === "All"
    ? STORE_PRODUCTS
    : STORE_PRODUCTS.filter((p) => p.category === activeCategory);

  return (
    <div className="demo-shop-root">
      {/* Top Announcement Bar */}
      <div className="demo-shop-announcement">
        <span>Free standard delivery on orders over $50 &bull; 30-day money-back guarantee</span>
        <div className="announcement-links">
          <span>Need Help? +1 (800) 555-0199</span>
          <span>&bull;</span>
          <a href="#support">Customer Support</a>
        </div>
      </div>

      {/* Main Navigation */}
      <header className="demo-shop-nav">
        <div className="demo-shop-nav-inner">
          <div className="demo-shop-brand">
            <div className="demo-shop-logo-icon">
              <ShoppingBag size={20} />
            </div>
            <span>DemoShop</span>
          </div>

          <nav className="demo-shop-menu">
            <a href="#home" className="demo-shop-menu-link active">
              Home
            </a>
            <a href="#products" className="demo-shop-menu-link">
              Products
            </a>
            <a href="#categories" className="demo-shop-menu-link">
              Categories
            </a>
            <a href="#about" className="demo-shop-menu-link">
              About
            </a>
            <a href="#contact" className="demo-shop-menu-link">
              Contact
            </a>
          </nav>

          <div className="demo-shop-nav-actions">
            <button className="nav-action-btn" title="My Account">
              <User size={18} />
              <span>Sign In</span>
            </button>
            <button className="nav-action-btn" title="Shopping Cart">
              <ShoppingCart size={18} />
              <span>Cart</span>
              {cartCount > 0 && <span className="cart-count">{cartCount}</span>}
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section with Product Search */}
      <section className="demo-shop-hero" id="home">
        <div className="demo-shop-hero-inner">
          <div className="hero-subtitle-tag">Winter 2026 Electronics Collection</div>
          <h1>Find Your Products</h1>
          <p>
            Explore our curated catalog of enterprise computers, mobile hardware, audio equipment, and workstation accessories.
          </p>

          {/* Search Bar */}
          <div className="demo-shop-search-bar">
            <Search size={20} color="#64748b" style={{ marginRight: 8 }} />
            <input
              type="text"
              className="demo-shop-search-input"
              placeholder="Search products by name (e.g. 'laptop', 'phone')..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleKeyDown}
            />
            <button
              className="demo-shop-search-btn"
              onClick={() => handleSearch()}
              disabled={searchLoading}
            >
              {searchLoading ? "Searching..." : "Search"}
            </button>
          </div>

          {/* Search Suggestions */}
          <div className="demo-shop-chips">
            <span className="demo-shop-chips-label">Popular searches:</span>
            <button className="demo-shop-chip" onClick={() => handleChipClick("laptop")}>
              laptop
            </button>
            <button className="demo-shop-chip" onClick={() => handleChipClick("phone")}>
              phone
            </button>
            <button className="demo-shop-chip" onClick={() => handleChipClick("headphones")}>
              headphones
            </button>
            <button className="demo-shop-chip" onClick={() => handleChipClick("keyboard")}>
              keyboard
            </button>
            <button className="demo-shop-chip" onClick={() => handleChipClick("monitor")}>
              monitor
            </button>
          </div>
        </div>
      </section>

      {/* Main Catalog View */}
      <main className="demo-shop-main" id="products">
        {/* Search Results Notification Banner */}
        {activeSearch && (
          <div className="search-results-banner">
            <div className="search-results-count">
              Search results for &ldquo;{activeSearch}&rdquo; ({searchResults.length}{" "}
              {searchResults.length === 1 ? "product" : "products"} found)
            </div>
            <button className="clear-search-btn" onClick={handleClearSearch}>
              &times; Clear Search
            </button>
          </div>
        )}

        {/* Category Filters (when not actively searching) */}
        {!activeSearch && (
          <div className="demo-shop-filters" id="categories">
            {CATEGORIES.map((cat) => (
              <button
                key={cat}
                className={`category-tab ${activeCategory === cat ? "active" : ""}`}
                onClick={() => setActiveCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>
        )}

        {/* Error Notice */}
        {searchError && (
          <div
            style={{
              padding: "16px 20px",
              background: "#fee2e2",
              color: "#991b1b",
              borderRadius: "8px",
              marginBottom: "24px",
              fontSize: "0.95rem",
            }}
          >
            {searchError}
          </div>
        )}

        {/* Product Cards Grid */}
        <div className="demo-shop-section-title">
          <span>{activeSearch ? "Matching Products" : `${activeCategory} Products`}</span>
          <span style={{ fontSize: "0.9rem", color: "#64748b", fontWeight: "normal" }}>
            {displayedProducts.length} {displayedProducts.length === 1 ? "item" : "items"} available
          </span>
        </div>

        {displayedProducts.length > 0 ? (
          <div className="demo-shop-grid">
            {displayedProducts.map((product) => (
              <div key={product.id} className="demo-shop-card">
                <div className="demo-shop-card-icon">{product.icon}</div>
                <div className="demo-shop-card-category">{product.category}</div>
                <div className="demo-shop-card-name">{product.name}</div>
                <div className="product-rating">
                  <Star size={14} fill="#f59e0b" color="#f59e0b" />
                  <span>{product.rating}</span>
                  <span className="product-rating-count">({product.reviews})</span>
                </div>
                <div className="demo-shop-card-price">${product.price.toFixed(2)}</div>
                <button
                  className="demo-shop-card-btn"
                  onClick={() => handleAddToCart(product.name)}
                >
                  <ShoppingCart size={16} /> Add to Cart
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: "64px 20px", color: "#64748b" }}>
            <p style={{ fontSize: "1.1rem", marginBottom: "16px" }}>
              No products found matching &ldquo;{activeSearch}&rdquo;.
            </p>
            <button className="clear-search-btn" onClick={handleClearSearch}>
              View All Products
            </button>
          </div>
        )}

        {/* Customer Trust / Value Propositions Banner */}
        <section className="demo-shop-features" id="about">
          <div className="feature-item">
            <div className="feature-icon-box">
              <Truck size={22} />
            </div>
            <div>
              <div className="feature-title">Free Express Shipping</div>
              <div className="feature-desc">Fast complimentary shipping on all orders over $50.</div>
            </div>
          </div>

          <div className="feature-item">
            <div className="feature-icon-box">
              <ShieldCheck size={22} />
            </div>
            <div>
              <div className="feature-title">2-Year Warranty</div>
              <div className="feature-desc">Comprehensive manufacturer warranty on all electronics.</div>
            </div>
          </div>

          <div className="feature-item">
            <div className="feature-icon-box">
              <RotateCcw size={22} />
            </div>
            <div>
              <div className="feature-title">30-Day Returns</div>
              <div className="feature-desc">Hassle-free return policy with prepaid shipping labels.</div>
            </div>
          </div>

          <div className="feature-item" id="support">
            <div className="feature-icon-box">
              <SupportIcon size={22} />
            </div>
            <div>
              <div className="feature-title">24/7 Dedicated Support</div>
              <div className="feature-desc">Expert technical specialists ready to assist your team.</div>
            </div>
          </div>
        </section>
      </main>

      {/* Cart Toast Notification */}
      {toastMessage && (
        <div className="demo-shop-toast">
          <Check size={18} color="#22c55e" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Modern E-Commerce Footer */}
      <footer className="demo-shop-footer" id="contact">
        <div className="footer-inner">
          <div className="footer-brand-col">
            <div className="demo-shop-brand" style={{ marginBottom: "12px" }}>
              <div className="demo-shop-logo-icon">
                <ShoppingBag size={18} />
              </div>
              <span>DemoShop</span>
            </div>
            <p>
              Your trusted enterprise source for high-performance hardware, workplace technology, and developer electronics.
            </p>
          </div>

          <div className="footer-col">
            <h4>Shop</h4>
            <ul>
              <li><a href="#products">Laptops & Computers</a></li>
              <li><a href="#products">Smartphones & Mobile</a></li>
              <li><a href="#products">Audio & Headsets</a></li>
              <li><a href="#products">Keyboards & Mice</a></li>
            </ul>
          </div>

          <div className="footer-col">
            <h4>Support</h4>
            <ul>
              <li><a href="#support">Order Tracking</a></li>
              <li><a href="#support">Shipping Policy</a></li>
              <li><a href="#support">Returns & Exchanges</a></li>
              <li><a href="#support">Contact Helpdesk</a></li>
            </ul>
          </div>

          <div className="footer-col">
            <h4>Company</h4>
            <ul>
              <li><a href="#about">About DemoShop</a></li>
              <li><a href="#about">Careers</a></li>
              <li><a href="#about">Privacy Policy</a></li>
              <li><a href="#about">Terms of Service</a></li>
            </ul>
          </div>
        </div>

        <div className="footer-bottom">
          <div>&copy; 2026 DemoShop Inc. All rights reserved.</div>
          <div>Secure 256-Bit SSL Encrypted E-Commerce Store</div>
        </div>
      </footer>
    </div>
  );
}
