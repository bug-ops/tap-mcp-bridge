//! Full e-commerce checkout flow example.
//!
//! This example demonstrates the complete TAP-authenticated e-commerce flow:
//! 1. Browse product catalog
//! 2. Get product details
//! 3. Add items to cart
//! 4. Update cart quantities
//! 5. Create order
//! 6. Process payment with APC encryption
//!
//! Run with: `cargo run --example full_checkout_flow`

#![allow(
    clippy::too_many_lines,
    clippy::print_stdout,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::uninlined_format_args,
    reason = "example code demonstrates API usage with verbose output"
)]

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::{
    error::Result,
    mcp::{
        cart::{AddToCartParams, GetCartParams, UpdateCartItemParams},
        models::Address,
        orders::CreateOrderParams,
        payment::{PaymentMethodParams, ProcessPaymentParams},
        products::{GetProductParams, GetProductsParams},
    },
    tap::TapSigner,
};

/// Sample merchant RSA public key (for demonstration only).
const MERCHANT_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----"#;

#[tokio::main]
async fn main() -> Result<()> {
    println!("TAP E-Commerce Checkout Flow Example");
    println!("=====================================\n");

    // Initialize TAP signer with agent credentials
    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    let agent_id = "shopping-agent-001";
    let agent_directory_url =
        "https://agent.example.com/.well-known/http-message-signatures-directory";

    let _signer = TapSigner::new(signing_key, agent_id, agent_directory_url);
    println!("Initialized TAP signer for agent: {}", agent_id);

    // Common parameters for all requests
    let merchant_url = "https://merchant.example.com";
    let consumer_id = "consumer-alice-123";

    // ACRO contextual data
    let country_code = "US";
    let zip = "94025";
    let ip_address = "192.168.1.100";
    let user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";
    let platform = "macOS";

    println!("\n1. Browsing Product Catalog");
    println!("----------------------------");

    // Step 1: Browse product catalog
    let _catalog_params = GetProductsParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
        category: Some("electronics".to_owned()),
        search: Some("laptop".to_owned()),
        page: Some(1),
        per_page: Some(20),
    };

    println!("Fetching products (category: electronics, search: laptop)...");
    println!("Note: This is a demonstration. In production, this would make a real API call.");

    // In a real implementation:
    // let catalog = get_products(&signer, catalog_params).await?;
    // println!("Found {} products", catalog.products.len());

    println!("\n2. Getting Product Details");
    println!("---------------------------");

    // Step 2: Get specific product details
    let _product_params = GetProductParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        product_id: "prod-laptop-15".to_owned(),
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
    };

    println!("Fetching product details for: prod-laptop-15...");

    // In a real implementation:
    // let product = get_product(&signer, product_params).await?;
    // println!("Product: {} - ${}", product.name, product.price);

    println!("\n3. Adding Items to Cart");
    println!("-----------------------");

    // Step 3: Add product to cart
    let _add_to_cart_params = AddToCartParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        cart_id: None, // None creates a new cart
        product_id: "prod-laptop-15".to_owned(),
        variant_id: Some("var-16gb-512gb".to_owned()),
        quantity: 1,
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
    };

    println!("Adding laptop to cart (variant: 16GB RAM, 512GB SSD)...");

    // In a real implementation:
    // let cart = add_to_cart(&signer, add_to_cart_params).await?;
    // let cart_id = cart.cart_id.clone();
    // println!("Cart ID: {}", cart_id);
    // println!("Subtotal: ${}", cart.subtotal);

    // For demonstration, simulate cart ID
    let cart_id = "cart-demo-12345";
    println!("Cart ID: {}", cart_id);

    println!("\n4. Adding More Items");
    println!("--------------------");

    // Add accessories
    let _add_accessory_params = AddToCartParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        cart_id: Some(cart_id.to_owned()),
        product_id: "prod-mouse-wireless".to_owned(),
        variant_id: None,
        quantity: 2,
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
    };

    println!("Adding wireless mouse (quantity: 2) to cart...");

    // In a real implementation:
    // let cart = add_to_cart(&signer, add_accessory_params).await?;
    // println!("Cart items: {}", cart.items.len());

    println!("\n5. Updating Cart Item");
    println!("---------------------");

    // Step 4: Update quantity
    let _update_params = UpdateCartItemParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        cart_id: cart_id.to_owned(),
        item_id: "item-mouse-001".to_owned(),
        quantity: 3, // Changed from 2 to 3
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
    };

    println!("Updating mouse quantity from 2 to 3...");

    // In a real implementation:
    // let cart = update_cart_item(&signer, update_params).await?;
    // println!("Updated subtotal: ${}", cart.subtotal);

    println!("\n6. Reviewing Cart");
    println!("-----------------");

    // Step 5: Get current cart state
    let _get_cart_params = GetCartParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        cart_id: cart_id.to_owned(),
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
    };

    println!("Fetching current cart state...");

    // In a real implementation:
    // let cart = get_cart(&signer, get_cart_params).await?;
    // println!("Subtotal: ${}", cart.subtotal);
    // println!("Tax: ${}", cart.tax);
    // println!("Shipping: ${}", cart.shipping.unwrap_or_default());
    // println!("Total: ${}", cart.total);

    println!("\n7. Creating Order");
    println!("-----------------");

    // Step 6: Create order with shipping information
    let shipping_address = Address {
        name: "Alice Johnson".to_owned(),
        street: "123 Main St, Apt 4B".to_owned(),
        city: "San Francisco".to_owned(),
        state: "CA".to_owned(),
        postal_code: "94025".to_owned(),
        country: "US".to_owned(),
        phone: Some("+1-415-555-1234".to_owned()),
    };

    let billing_address = Address {
        name: "Alice Johnson".to_owned(),
        street: "456 Billing Ave".to_owned(),
        city: "Palo Alto".to_owned(),
        state: "CA".to_owned(),
        postal_code: "94301".to_owned(),
        country: "US".to_owned(),
        phone: None,
    };

    let _create_order_params = CreateOrderParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        cart_id: cart_id.to_owned(),
        shipping_address,
        billing_address: Some(billing_address),
        delivery_option: Some("express".to_owned()),
        promo_code: Some("WELCOME10".to_owned()),
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
    };

    println!("Creating order with express shipping and promo code WELCOME10...");

    // In a real implementation:
    // let order = create_order(&signer, create_order_params).await?;
    // let order_id = order.order_id.clone();
    // println!("Order ID: {}", order_id);
    // println!("Order status: {:?}", order.status);
    // println!("Order total: ${}", order.total);

    // For demonstration
    let order_id = "order-demo-67890";
    println!("Order ID: {}", order_id);

    println!("\n8. Processing Payment");
    println!("---------------------");

    // Step 7: Process payment with encrypted card data
    let payment_method = PaymentMethodParams::Card {
        card_number: "4111111111111111".to_owned(),
        expiry_month: "12".to_owned(),
        expiry_year: "2027".to_owned(),
        cvv: "123".to_owned(),
        cardholder_name: "Alice Johnson".to_owned(),
    };

    let _payment_params = ProcessPaymentParams {
        merchant_url: merchant_url.to_owned(),
        consumer_id: consumer_id.to_owned(),
        order_id: order_id.to_owned(),
        payment_method,
        merchant_public_key_pem: MERCHANT_PUBLIC_KEY_PEM.to_owned(),
        country_code: country_code.to_owned(),
        zip: zip.to_owned(),
        ip_address: ip_address.to_owned(),
        user_agent: user_agent.to_owned(),
        platform: platform.to_owned(),
    };

    println!("Processing payment with encrypted card data (APC)...");
    println!("Card will be encrypted using merchant's RSA public key.");

    // In a real implementation:
    // let payment_result = process_payment(&signer, payment_params).await?;
    // println!("Transaction ID: {}", payment_result.transaction_id);
    // println!("Payment status: {:?}", payment_result.status);
    //
    // if let Some(message) = payment_result.message {
    //     println!("Message: {}", message);
    // }

    println!("\n9. Order Complete");
    println!("-----------------");
    println!("Transaction ID: txn-demo-abc123");
    println!("Payment status: Approved");
    println!("Order status: Processing");
    println!("\nThank you for your purchase!");

    println!("\n\nSECURITY HIGHLIGHTS");
    println!("===================");
    println!("- All requests authenticated with TAP signatures (RFC 9421)");
    println!("- Payment credentials encrypted in APC (RSA-OAEP-256 + A256GCM)");
    println!("- Consumer context provided in ACRO (location, device info)");
    println!("- Agent identity verified via directory URL");
    println!("- No sensitive data exposed in logs or errors");

    Ok(())
}
