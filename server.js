import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import Bottleneck from "bottleneck";
import cors from "cors"; // 💡 NEW: Import the CORS package

dotenv.config();
const app = express();


// --- CORS Configuration ---
// --- CORS Configuration ---
const allowedOrigins = [
  'https://velonia.si',                       
  'https://www.velonia.si',                   // 💡 FIX 1: Add the common 'www' version
  'https://s0jd0m-rg.myshopify.com',
  'https://shopify-auto-bundle-dashboard.vercel.app', // 💡 FIX 2: Explicitly allow the app's hosting domain (Vercel)
]; 
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl) or if the origin is in our list
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: 'GET,POST,PUT,DELETE', // Allow the necessary methods (especially POST for tracking)
  allowedHeaders: 'Content-Type,Authorization',
  credentials: true
};

app.use(cors(corsOptions));


// Configure Bottleneck for rate limiting (2 requests per second)
const limiter = new Bottleneck({
  minTime: 500, // 500ms between requests (2 requests per second)
  maxConcurrent: 1 // Process one request at a time
});

// Wrap axios methods with limiter
const limitedAxiosGet = limiter.wrap(axios.get);
const limitedAxiosPost = limiter.wrap(axios.post);
const limitedAxiosPut = limiter.wrap(axios.put);
const limitedAxiosDelete = limiter.wrap(axios.delete);

// Define global constants early for helper function access
// const SHOP = process.env.SHOP;
// const TOKEN = process.env.TOKEN;
// const API_VERSION = "2025-10";

const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY; // Public API Key from Partner Dashboard
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET; // Secret Key
const HOST = process.env.HOST; // Your app's public URL (e.g., from Vercel)
const SCOPES = 'read_products, write_products, read_inventory, write_inventory, read_orders';
const API_VERSION = "2025-10";

const shopsStore = {};

const getDynamicCredentials = (req) => {
    const shop = req.query.shop || req.body.shop;
    const tokenData = shop ? shopsStore[shop] : null;

    if (!shop || !tokenData) {
        // Fallback to hardcoded .env credentials if shop/session are missing (Legacy/Local Dev)
        // WARNING: This check is ONLY for local development comfort. Remove it for production Public App.
        if (process.env.SHOP && process.env.TOKEN) {
            return { shop: process.env.SHOP, token: process.env.TOKEN, status: 'fallback' };
        }
        return { shop: null, token: null, status: 'unauthorized' };
    }
    return { shop: shop, token: tokenData.accessToken, status: 'ok' };
};

// Helper function for Shopify REST API calls with retry logic for 429 errors
async function shopifyApiCall(shopDomain, accessToken, method, url, data = null) {
  const maxRetries = 3;
  let attempt = 0;
  const fullUrl = `https://${shopDomain}${url}`;
  const headers = { "X-Shopify-Access-Token": accessToken, "Content-Type": "application/json" };

  while (attempt < maxRetries) {
    try {
      if (method === "get") {
        return await limitedAxiosGet(fullUrl, { headers });
      } else if (method === "post") {
        return await limitedAxiosPost(fullUrl, data, { headers });
      } else if (method === "put") {
        return await limitedAxiosPut(fullUrl, data, { headers });
      } else if (method === "delete") {
        return await limitedAxiosDelete(fullUrl, { headers });
      }
    } catch (err) {
      if (err.response?.status === 429) {
        const retryAfter = parseInt(err.response.headers["retry-after"] || 2, 10) * 1000;
        console.log(`Rate limit hit for ${fullUrl}, retrying after ${retryAfter}ms (attempt ${attempt + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, retryAfter));
        attempt++;
        continue;
      }
      throw new Error(`API call failed: ${err.message}${err.response ? `, status: ${err.response.status}, data: ${JSON.stringify(err.response.data)}` : ''}`);
    }
  }
  throw new Error(`Max retries (${maxRetries}) exceeded for ${fullUrl}`);
}

// Helper function for Shopify GraphQL calls
async function shopifyGraphQLCall(shopDomain, accessToken, query, variables = {}) {
  const url = `https://${shopDomain}/admin/api/${API_VERSION}/graphql.json`;
  const headers = { "X-Shopify-Access-Token": accessToken, "Content-Type": "application/json" };
  const postData = { query, variables };
  const maxRetries = 3;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      const response = await limitedAxiosPost(url, postData, { headers });
      const graphData = response.data;
      if (!graphData || typeof graphData !== 'object') {
        throw new Error(`Invalid GraphQL response: ${JSON.stringify(response.data)}`);
      }
      if (graphData.errors) {
        const hasThrottled = graphData.errors.some(e => e.extensions?.code === "THROTTLED");
        if (hasThrottled) {
          const retryAfter = 2000;
          console.log(`GraphQL throttled, retrying after ${retryAfter}ms (attempt ${attempt + 1}/${maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, retryAfter));
          attempt++;
          continue;
        }
        throw new Error(`GraphQL errors: ${JSON.stringify(graphData.errors)}`);
      }
      if (!graphData.data) {
        throw new Error(`GraphQL response missing 'data' field: ${JSON.stringify(graphData)}`);
      }
      return graphData.data;
    } catch (err) {
      if (err.response?.status === 429) {
        const retryAfter = parseInt(err.response.headers["retry-after"] || 2, 10) * 1000;
        console.log(`Rate limit hit for GraphQL, retrying after ${retryAfter}ms (attempt ${attempt + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, retryAfter));
        attempt++;
        continue;
      }
      throw new Error(`GraphQL call failed: ${err.message}${err.response ? `, status: ${err.response.status}, data: ${JSON.stringify(err.response.data)}` : ''}`);
    }
  }
  throw new Error(`Max retries (${maxRetries}) exceeded for GraphQL`);
}

// Route 1: Installation starts here
app.get('/shopify/install', (req, res) => {
    const shop = req.query.shop;
    if (!shop) {
        return res.status(400).send('Missing shop parameter');
    }

    const state = crypto.randomBytes(16).toString('hex');
    const redirectUri = `${HOST}/shopify/callback`;
    const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SCOPES}&state=${state}&redirect_uri=${redirectUri}`;

    res.cookie('state', state); // Store state for validation
    res.redirect(installUrl);
});

// Route 2: Callback handles token exchange
app.get('/shopify/callback', async (req, res) => {
    const { shop, code, state } = req.query;
    const storedState = req.cookies ? req.cookies.state : null;

    if (state !== storedState) {
        return res.status(400).send('State token mismatch');
    }

    if (!shop || !code) {
        return res.status(400).send('Missing required OAuth parameters');
    }
    
    const accessTokenRequestUrl = `https://${shop}/admin/oauth/access_token`;
    const accessTokenPayload = {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
    };

    try {
        const response = await axios.post(accessTokenRequestUrl, accessTokenPayload);
        const accessToken = response.data.access_token;

        // Store the permanent token and shop URL
        shopsStore[shop] = { accessToken };
        
        // Redirect to the main app dashboard, passing the shop domain
        res.redirect(`/?shop=${shop}`);

    } catch (error) {
        console.error("Error exchanging code for access token:", error.response?.data || error.message);
        res.status(500).send('OAuth Failed');
    }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // <--- 💡 PASTE THIS LINE
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "ALLOWALL");
  next();
});

// Validate environment variables
if (!SHOP || !TOKEN) {
  console.error("Error: SHOP and TOKEN must be defined in .env file");
  process.exit(1);
}

// --- GraphQL Mutations ---

const PRODUCT_VARIANTS_BULK_UPDATE_MUTATION = `
  mutation productVariantsBulkUpdate($productId: ID!, $variants: [ProductVariantsBulkInput!]!) {
    productVariantsBulkUpdate(productId: $productId, variants: $variants) {
      product {
        id
      }
      productVariants {
        id
        price
        inventoryItem {
          id
        }
      }
      userErrors {
        field
        message
      }
    }
  }
`;

const PRODUCT_VARIANTS_BULK_CREATE_MUTATION = `
  mutation productVariantsBulkCreate($productId: ID!, $variants: [ProductVariantsBulkInput!]!) {
    productVariantsBulkCreate(productId: $productId, variants: $variants) {
      product {
        id
      }
      productVariants {
        id
        sku
        price
        inventoryItem {
          id
        }
        image {
          id
          src
        }
      }
      userErrors {
        field
        message
      }
    }
  }
`;


// --- GraphQL Queries for Reporting ---
// Around line 208
// Replace the existing BUNDLE_VARIANT_SALES_QUERY (around line 208)
// REPLACE the existing BUNDLE_VARIANT_SALES_QUERY (around line 208) with this:

// --- GraphQL Queries for Reporting ---
// Around line 208
// Replace the existing BUNDLE_VARIANT_SALES_QUERY (around line 208)
// REPLACE the existing BUNDLE_VARIANT_SALES_QUERY (around line 208) with this:

const BUNDLE_VARIANT_SALES_QUERY = (variantIds) => ` 
  query GetVariantSales($cursor: String) { 
    orders(first: 250, after: $cursor) { 
      edges { 
        node { 
          createdAt 
          lineItems(first: 250) { 
            edges { 
              node { 
                variant { 
                  id 
                } 
                quantity 
                sku 
              } 
            } 
          } 
        } 
      } 
      pageInfo { 
        hasNextPage 
        endCursor 
      } 
    } 
  } 
`;
// --- Fetching Logic ---
// --- Existing Product Fetching Logic (Updated to return mapped products) ---
// Replace your entire async function fetchProductsAndBundles() with this:
// Replace the entire existing fetchProductsAndBundles function (around line 312)

// REPLACE the entire existing fetchProductsAndBundles function

// REPLACE the entire existing fetchProductsAndBundles function (around line 315) with this:

// REPLACE the entire existing fetchProductsAndBundles function (around line 315) with this:

// REPLACE the entire existing fetchProductsAndBundles function (around line 315) with this:

// REPLACE the entire existing fetchProductsAndBundles function (around line 315) with this:

// REPLACE the provided async function fetchProductsAndBundles() with this:
// --- Fetching Logic ---
async function fetchProductsAndBundles(shopDomain, accessToken) {
    let products = [];
    let allUniqueTags = new Set(); 
    let cursor = null;
    let allBundleVariantGids = []; 
    let skuToGidMap = new Map();

    const query = `
        query fetchProducts($first: Int!, $after: String) {
            products(first: $first, after: $after) {
                edges {
                    node {
                        id
                        title
                        tags
                        metafield(namespace: "${VISITOR_NAMESPACE}", key: "${VISITOR_KEY}") { 
                            value
                        }
                        options {
                            id
                            name
                            values
                        }
                        variants(first: 10) {
                            edges {
                                node {
                                    id
                                    sku
                                    selectedOptions {
                                        name
                                        value
                                    }
                                    price
                                    inventoryItem {
                                        id
                                        inventoryLevels(first: 1) {
                                            edges {
                                                node {
                                                    quantities(names: ["available"]) {
                                                        name
                                                        quantity
                                                    }
                                                    location {
                                                        id
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        images(first: 1) {
                            edges {
                                node {
                                    id
                                    src
                                }
                            }
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
    `;

    try {
        let hasNextPage = true;
        while (hasNextPage) {
            // Updated call
            const data = await shopifyGraphQLCall(shopDomain, accessToken, query, { first: 250, after: cursor });
            if (!data || !data.products || !data.products.edges) {
                throw new Error(`Invalid response structure: ${JSON.stringify(data)}`);
            }

            products = products.concat(data.products.edges.map(e => e.node));
            cursor = data.products.pageInfo.endCursor;
            hasNextPage = data.products.pageInfo.hasNextPage;
        }

        const mappedProducts = products
            .map(product => {
                const dailyVisitsJson = product.metafield?.value;
                let totalVisitors = 0;

                if (dailyVisitsJson) {
                    try {
                        const dailyVisitsMap = JSON.parse(dailyVisitsJson);
                        totalVisitors = Object.values(dailyVisitsMap).reduce((sum, item) => sum + item, 0);
                    } catch (e) {
                        // Silent error if JSON fails to parse
                    }
                }

                const mappedProduct = {
                    id: product.id.split('/').pop(),
                    title: product.title,
                    visitors: totalVisitors, 
                    variants: product.variants?.edges?.map(e => e.node) || [],
                    options: product.options,
                    tags: product.tags
                };
                
                (product.tags || []).forEach(tag => allUniqueTags.add(tag.trim().toLowerCase()));

                return mappedProduct;
            });

        const filteredProducts = mappedProducts
            .filter(product => {
                const variants = product.variants;
                
                const baseVariant = variants.find(v => {
                    const option1 = v.selectedOptions.find(opt => opt.name === "Bundle")?.value;
                    return !["1x", "2x", "3x"].includes(option1);
                }) || variants[0];

                if (!baseVariant) return false;

                const baseInventory = baseVariant.inventoryItem?.inventoryLevels.edges[0]?.node.quantities.find(q => q.name === "available")?.quantity || 0;

                const hasBundleVariants = variants.some(v => {
                    const option1 = v.selectedOptions.find(opt => opt.name === "Bundle")?.value;
                    return ["1x", "2x", "3x"].includes(option1);
                });

                const hasNonBundleOptions = product.options.some(opt => opt.name !== "Bundle" && opt.name !== "Title");

                return baseInventory > 3 && !hasBundleVariants && !hasNonBundleOptions;
            })
            .sort((a, b) => a.title.localeCompare(b.title));

        const bundledProducts = mappedProducts
            .filter(product =>
                // FIX: Use the most lenient filter: check if ANY variant has the bundle option value.
                product.variants.some(variant => {
                    const option1 = variant.selectedOptions.find(opt => opt.name === "Bundle")?.value;
                    return ["1x", "2x", "3x"].includes(option1);
                })
            )
            .map(product => {
                let bundles = [];
                const visitorCount = product.visitors;
                
                (product.variants || []).forEach(variant => { 
                    const option1 = variant.selectedOptions.find(opt => opt.name === "Bundle")?.value;
                    
                    if (["1x", "2x", "3x"].includes(option1)) {
                        const available = variant.inventoryItem.inventoryLevels.edges[0]?.node.quantities.find(q => q.name === "available")?.quantity || 0;
                        
                        allBundleVariantGids.push(variant.id);
                        skuToGidMap.set(variant.sku, variant.id); 

                        bundles.push({
                            type: option1,
                            variantId: variant.id.split('/').pop(),
                            variantGid: variant.id, 
                            price: parseFloat(variant.price).toFixed(2),
                            available,
                            totalOrders: 0, 
                        });
                    }
                });
                
                if (bundles.length > 0) {
                    bundles.sort((a, b) => parseInt(a.type) - parseInt(b.type));
                    return { 
                        id: product.id.split('/').pop(), 
                        title: product.title, 
                        bundles, 
                        tags: product.tags,
                        visitors: visitorCount
                    };
                }
                return null;
            })
            .filter(p => p !== null)
            .sort((a, b) => a.title.localeCompare(b.title));
            
        // Updated call
        const salesMap = await fetchAndAggregateSales(shopDomain, accessToken, allBundleVariantGids, skuToGidMap);

        bundledProducts.forEach(product => {
            product.bundles.forEach(bundle => {
                bundle.totalOrders = salesMap.get(bundle.variantGid) || 0;
            });
        });

        return { 
            filteredProducts, 
            bundledProducts,
            allUniqueTags: Array.from(allUniqueTags).sort()
        };
    } catch (err) {
        console.error("Error in fetchProductsAndBundles:", err.message);
        throw new Error(`Failed to fetch products: ${err.message}`);
    }
}
async function fetchData() {
    // Only one API call needed now
    return fetchProductsAndBundles(); 
}

// 💡 NEW HELPER FUNCTION
// Replace the entire existing fetchAndAggregateSales function (around line 527)

// REPLACE the entire existing fetchAndAggregateSales function (around line 527) with this new version:

// 💡 NEW HELPER FUNCTION
// Replace the entire existing fetchAndAggregateSales function (around line 527)

// REPLACE the entire existing fetchAndAggregateSales function (around line 527) with this new version:

// 💡 HELPER FUNCTION: Fetches and aggregates sales data
async function fetchAndAggregateSales(shopDomain, accessToken, variantGids, skuToGidMap, dateFilter = "") {
    if (variantGids.length === 0) return new Map();

    const finalGidSalesMap = new Map();
    const allBundleSkus = new Set(skuToGidMap.keys());
    
    const CHUNK_SIZE = 50; 
    const chunks = [];
    for (let i = 0; i < variantGids.length; i += CHUNK_SIZE) {
        chunks.push(variantGids.slice(i, i + CHUNK_SIZE));
    }
    
    // Process chunks sequentially
    for (const chunk of chunks) {
        let chunkCursor = null;
        let chunkHasNextPage = true;
        let pageCount = 0;
        const MAX_PAGES = 10; 

        while (chunkHasNextPage && pageCount < MAX_PAGES) { 
            const query = BUNDLE_VARIANT_SALES_QUERY(chunk, dateFilter);
            
            // Updated call
            const data = await shopifyGraphQLCall(shopDomain, accessToken, query, { cursor: chunkCursor }); 
            
            const orders = data?.orders?.edges || []; 
            pageCount++;

            orders.forEach(orderEdge => { 
                if (!orderEdge.node.createdAt) return;

                orderEdge.node.lineItems.edges.forEach(lineItemEdge => { 
                    const variantId = lineItemEdge.node.variant?.id;
                    const quantity = lineItemEdge.node.quantity;
                    
                    if (variantId && chunk.includes(variantId)) {
                        // For the purpose of this demo, we're simplifying aggregation 
                        // by only counting total orders per GID.
                        finalGidSalesMap.set(variantId, (finalGidSalesMap.get(variantId) || 0) + quantity);
                    }
                }); 
            }); 

            chunkCursor = data.orders.pageInfo.endCursor; 
            chunkHasNextPage = data.orders.pageInfo.hasNextPage;

            if(chunkHasNextPage) {
                await new Promise(resolve => setTimeout(resolve, 500)); 
            }
        } 
    }
    
    return finalGidSalesMap; 
}
async function fetchBundleMappings() {
  let mappings = [];
  let cursor = null;
  const query = `
    query fetchProducts($first: Int!, $after: String) {
      products(first: $first, after: $after) {
        edges {
          node {
            id
            options {
              id
              name
              values
            }
            variants(first: 10) {
              edges {
                node {
                  id
                  selectedOptions {
                    name
                    value
                  }
                }
              }
            }
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  `;

  try {
    let hasNextPage = true;
    while (hasNextPage) {
      const data = await shopifyGraphQLCall(query, { first: 250, after: cursor });
      if (!data || !data.products || !data.products.edges) {
        throw new Error(`Invalid response structure: ${JSON.stringify(data)}`);
      }
      const prods = data.products.edges.map(e => e.node);
      const bundleProds = prods.filter(p =>
        p.options.some(opt =>
          opt.name === "Bundle" &&
          opt.values.includes("1x") &&
          opt.values.includes("2x") &&
          opt.values.includes("3x")
        )
      );
      mappings = mappings.concat(bundleProds.map(p => {
        const variantIds = { "1x": null, "2x": null, "3x": null };
        // ✅ FIX 3: Safely access variants.edges
        (p.variants?.edges || []).forEach(({ node }) => {
          const option1 = node.selectedOptions.find(opt => opt.name === "Bundle")?.value;
          if (["1x", "2x", "3x"].includes(option1)) {
            variantIds[option1] = node.id.split('/').pop();
          }
        });
        return {
          product_id: p.id.split('/').pop().toString(),
          variant_ids: variantIds
        };
      }));
      cursor = data.products.pageInfo.endCursor;
      hasNextPage = data.products.pageInfo.hasNextPage;
    }

    return mappings;
  } catch (err) {
    console.error("Error in fetchBundleMappings:", err.message);
    throw new Error(`Failed to fetch bundle mappings: ${err.message}`);
  }
}
// ... (existing code before app.get("/") route)

// --- Metafield Constants (Ensure these match your created metafield) ---
// --- Metafield Constants (Ensure these match your created metafield) ---
const VISITOR_NAMESPACE = "bundle";
// 💡 CHANGE: Use a new key for daily tracking
const VISITOR_KEY = "daily_visits"; 
// 💡 CHANGE: Use JSON type to store map of { "YYYY-MM-DD": count }
const VISITOR_TYPE = "json"; 

// Old constant (for reference/cleanup, if needed):
const LEGACY_VISITOR_KEY = "visitors";

// 💡 NEW: Endpoint to track visitors and increment the metafield
const VISITORS_UPDATE_MUTATION = `
  mutation SetMetafield($metafields: [MetafieldsSetInput!]!) {
    metafieldsSet(metafields: $metafields) {
      metafields {
        id
        value
      }
      userErrors {
        field
        message
      }
    }
  }
`;

// 💡 NEW GRAPHQL QUERY for fetching the current count
// 💡 NEW GRAPHQL QUERY for fetching the current JSON count
const VISITORS_FETCH_QUERY = `
  query GetVisitorCount($id: ID!) {
    product(id: $id) {
      metafield(namespace: "${VISITOR_NAMESPACE}", key: "${VISITOR_KEY}") {
        value
      }
      legacyMetafield: metafield(namespace: "${VISITOR_NAMESPACE}", key: "${LEGACY_VISITOR_KEY}") {
        value
      }
    }
  }
`;



// 💡 FINAL GRAPHQL FUNCTION: Uses GraphQL for persistence and relies on shopifyGraphQLCall
app.post("/track-bundle-visit", async (req, res) => {
  const { product_id } = req.body;
  const productGid = `gid://shopify/Product/${product_id}`;
  const todayDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

  if (!product_id) {
    return res.status(400).json({ success: false, message: "Product ID required." });
  }

  try {
    // 1. FETCH: Retrieve the existing JSON metafield (and legacy total)
    const fetchResponse = await shopifyGraphQLCall(VISITORS_FETCH_QUERY, { id: productGid });
    
    const metafieldData = fetchResponse?.product;
    const jsonMetafield = metafieldData?.metafield;
    
    let dailyCounts = {}; // Stores { "YYYY-MM-DD": count, ... }
    let totalVisitors = 0;

    // A. Load existing daily data
    if (jsonMetafield && jsonMetafield.value) {
        try {
            dailyCounts = JSON.parse(jsonMetafield.value);
            // Calculate current total visitors from daily counts
            totalVisitors = Object.values(dailyCounts).reduce((sum, count) => sum + count, 0);
        } catch (e) {
            console.warn(`Could not parse JSON for ${product_id}: ${jsonMetafield.value}. Initializing new map.`);
        }
    } 
    
    // B. Handle initialization/legacy migration (Optional: Run only once if needed)
    // If we have no daily counts but an old total exists, seed the totalVisitors count with it
    const legacyMetafield = metafieldData?.legacyMetafield;
    if (totalVisitors === 0 && legacyMetafield && legacyMetafield.value) {
        const legacyCount = parseInt(legacyMetafield.value, 10);
        if (!isNaN(legacyCount)) {
            totalVisitors = legacyCount;
        }
    }

    // 2. INCREMENT TODAY'S COUNT
    const previousDailyCount = dailyCounts[todayDate] || 0;
    const newDailyCount = previousDailyCount + 1;
    
    dailyCounts[todayDate] = newDailyCount;
    totalVisitors++; // Increment the overall total

    // 3. WRITE: Set the updated daily counts JSON
    const variables = {
      metafields: [{
        ownerId: productGid,
        namespace: VISITOR_NAMESPACE,
        key: VISITOR_KEY,
        value: JSON.stringify(dailyCounts), 
        type: VISITOR_TYPE, // json
      }]
    };

    const updateResponse = await shopifyGraphQLCall(VISITORS_UPDATE_MUTATION, variables);
    
    const userErrors = updateResponse?.metafieldsSet?.userErrors || [];
    if (userErrors.length > 0) {
      throw new Error(`GraphQL Metafield Set Error: ${JSON.stringify(userErrors)}`);
    }

    // 4. LOGGING
    console.log(`✅ Visitor count updated for product ${product_id}. Today (${todayDate}): ${previousDailyCount} → ${newDailyCount}. Total: ${totalVisitors}.`);
    res.json({ success: true, count: newDailyCount, total: totalVisitors });

  } catch (error) {
    console.error(`Error tracking bundle visit for product ${product_id}: ${error.message}`);
    res.status(500).json({ success: false, message: error.message });
  }
});
// --- Express Routes ---
// The main dashboard handler
app.get("/", async (req, res) => {
    // 💡 CREDENTIAL RETRIEVAL: Must be done first
    const { shop, token, status } = getDynamicCredentials(req);
    
    if (status === 'unauthorized') {
        // Redirect to install flow if the shop parameter is missing or unauthorized
        const shopParam = req.query.shop;
        if (shopParam) {
            return res.redirect(`/shopify/install?shop=${shopParam}`);
        }
        return res.status(401).send("Shop parameter required to install the app.");
    }
    
    try {
        // Updated call: Passing shop and token to fetchData
        const { filteredProducts, bundledProducts, allUniqueTags } = await fetchData(shop, token); 
        
        res.render("index", { 
            products: filteredProducts, 
            bundledProducts, 
            marketCollections: allUniqueTags.map(tag => ({ title: tag.toUpperCase(), tag })),
            shopDomain: shop, // Pass the dynamic shop domain
            message: req.query.message 
        });
    } catch (err) {
        console.error("Error fetching data in GET /:", err);
        res.status(500).send(`Error fetching data: ${err.message}`);
    }
});
// Create Bundles handler
app.post("/create-bundles", async (req, res) => {
    // 1. DYNAMIC CREDENTIAL RETRIEVAL
    const { shop, token, status } = getDynamicCredentials(req);
    if (status !== 'ok' && status !== 'fallback') {
        return res.status(401).send("Unauthorized");
    }
    const LOCAL_API_VERSION = "2025-01";
    let { product_ids, discount2 = 0, discount3 = 0, add_image = "false", bundle_text } = req.body;
    
    if (!bundle_text) {
        bundle_text = ""; 
    }
    
    product_ids = Array.isArray(product_ids) ? product_ids : [product_ids];
    discount2 = parseFloat(discount2);
    discount3 = parseFloat(discount3);
    add_image = add_image === "true";

    if (!product_ids || product_ids.length === 0) {
      return res.redirect(
        `/?message=${encodeURIComponent("❌ Error: At least one Product ID is required.")}`
      );
    }

    // --- LOCAL DYNAMIC API HELPERS ---
    const shopifyGraphQLCallLocal = (query, variables = {}) => shopifyGraphQLCall(shop, token, query, variables);
    const shopifyApiCallLocal = (method, url, data = null) => shopifyApiCall(shop, token, method, url, data);
    // --- END LOCAL DYNAMIC API HELPERS ---
    
    // Remove Default Title variant
    const removeDefaultVariant = async (productId) => {
      try {
        const query = `
          query {
            product(id: "gid://shopify/Product/${productId}") {
              variants(first: 10) { edges { node { id title } } }
              images(first: 1) { edges { node { id src } } }
            }
          }
        `;
        const data = await shopifyGraphQLCallLocal(query);
        const variants = data.product?.variants?.edges || [];
        const defaultVar = variants.find((v) => v.node.title === "Default Title");

        if (defaultVar) {
          const variantIdNum = defaultVar.node.id.split("/").pop();
          const variantUrl = `/admin/api/${LOCAL_API_VERSION}/products/${productId}/variants/${variantIdNum}.json`;
          await shopifyApiCallLocal("delete", variantUrl);
          console.log(`🗑️ Deleted Default Title variant for product ${productId}`);
        }

        const mainImageNode = data.product?.images?.edges?.[0]?.node || null;
        return mainImageNode;
      } catch (err) {
        console.warn(`⚠️ Error removing Default Title for ${productId}: ${err.message}`);
        return null;
      }
    };

    const chunkArray = (arr, size) => {
      const chunks = [];
      for (let i = 0; i < arr.length; i += size) chunks.push(arr.slice(i, i + size));
      return chunks;
    };

    // --- CORE PROCESSING LOGIC ---
    const processProduct = async (product_id) => {
      try {
        const productQuery = `
          query getProduct($id: ID!) {
            product(id: $id) {
              id
              title
              options { id name values }
              variants(first: 10) {
                edges {
                  node {
                    id
                    selectedOptions { name value }
                    price
                    sku
                    inventoryItem {
                      id
                      inventoryLevels(first: 1) {
                        edges {
                          node {
                            quantities(names: ["available"]) { name quantity }
                            location { id }
                          }
                        }
                      }
                    }
                  }
                }
              }
              images(first: 1) { edges { node { id src } } }
            }
          }
        `;

        const productGid = `gid://shopify/Product/${product_id}`;
        let data = await shopifyGraphQLCallLocal(productQuery, { id: productGid });
        const product = data?.product;
        if (!product) throw new Error(`Product not found (${product_id})`);
        
        // --- Set bundle.extra_text metafield using REST API ---
        if (bundle_text !== "") {
            const metafieldUrl = `/admin/api/${LOCAL_API_VERSION}/products/${product_id}/metafields.json`;
            const metafieldData = {
                metafield: {
                    namespace: "bundle", key: "extra_text", value: bundle_text, type: "single_line_text_field" 
                }
            };
            await shopifyApiCallLocal("post", metafieldUrl, metafieldData);
        }

        const variants = product.variants.edges.map((e) => e.node);
        if (!variants.length) throw new Error("No variants found.");

        // --- CHECK VARIANTS, INVENTORY, LOCATION ---
        const baseVariant =
          variants.find((v) => {
            const opt = v.selectedOptions.find((o) => o.name === "Bundle");
            return !opt || !["1x", "2x", "3x"].includes(opt.value);
          }) || variants[0];

        const basePrice = parseFloat(baseVariant.price);
        const baseInventoryLevel = baseVariant.inventoryItem.inventoryLevels.edges[0]?.node;
        const baseInventory =
          baseInventoryLevel?.quantities.find((q) => q.name === "available")?.quantity || 0;
        const locationId = baseInventoryLevel?.location?.id;

        if (!locationId) throw new Error("No inventory location found.");
        if (baseInventory <= 0) throw new Error("No inventory available.");
        // --- END CHECK VARIANTS, INVENTORY, LOCATION ---


        // Delete old variants
        for (const variant of variants) {
          const variantId = variant.id.split("/").pop();
          const variantUrl = `/admin/api/${LOCAL_API_VERSION}/products/${product_id}/variants/${variantId}.json`;
          try { await shopifyApiCallLocal("delete", variantUrl); } catch {}
        }

        // Update product options
        const productUrl = `/admin/api/${LOCAL_API_VERSION}/products/${product_id}.json`;
        await shopifyApiCallLocal("put", productUrl, {
          product: { id: product_id, options: [{ name: "Bundle", values: ["1x", "2x", "3x"] }] },
        });

        data = await shopifyGraphQLCallLocal(productQuery, { id: productGid });
        const bundleOption = data?.product?.options.find((opt) => opt.name === "Bundle");
        if (!bundleOption) throw new Error("Bundle option not found after update.");

        // Prepare bundles
        const bundles = [
          { title: "1x Bundle", qty: 1, price: basePrice, inventory: Math.floor(baseInventory / 1) },
          { title: "2x Bundle", qty: 2, price: basePrice * 2 * (1 - discount2 / 100), inventory: Math.floor(baseInventory / 2) },
          { title: "3x Bundle", qty: 3, price: basePrice * 3 * (1 - discount3 / 100), inventory: Math.floor(baseInventory / 3) },
        ];

        const variantsToCreate = bundles.map((b) => ({
          optionValues: [{ optionId: bundleOption.id, name: `${b.qty}x` }],
          price: b.price.toFixed(2),
          inventoryItem: { sku: `${product_id}-${b.qty}x-BUNDLE` },
          inventoryQuantities: [{ locationId, availableQuantity: b.inventory }],
        }));

        const PRODUCT_VARIANTS_BULK_CREATE_MUTATION = `
          mutation ProductVariantsBulkCreate($productId: ID!, $variants: [ProductVariantsBulkInput!]!) {
            productVariantsBulkCreate(productId: $productId, variants: $variants) {
              productVariants { id title }
              userErrors { field message }
            }
          }
        `;

        // Updated call: Bulk create new variants
        const createData = await shopifyGraphQLCallLocal(PRODUCT_VARIANTS_BULK_CREATE_MUTATION, {
          productId: product.id,
          variants: variantsToCreate,
        });

        if (createData.productVariantsBulkCreate.userErrors.length) {
          throw new Error(JSON.stringify(createData.productVariantsBulkCreate.userErrors));
        }

        // Remove Default Title & get main image
        const mainImageNode = await removeDefaultVariant(product_id);

        // Updated call: REST image upload
        if (add_image && mainImageNode) {
          const mainImageId = mainImageNode.id.split("/").pop();
          for (const variant of createData.productVariantsBulkCreate.productVariants) {
            const variantIdNum = variant.id.split("/").pop();
            const variantUrl = `/admin/api/${LOCAL_API_VERSION}/products/${product_id}/variants/${variantIdNum}.json`;
            try {
              await shopifyApiCallLocal("put", variantUrl, { variant: { id: variantIdNum, image_id: mainImageId } });
            } catch (err) {
              console.warn(`⚠️ Could not link image for variant ${variantIdNum}: ${err.message}`);
            }
          }
        }

        return { product_id, success: `✅ Bundles created successfully for product ${product_id}` };

      } catch (err) {
        console.error(`❌ Error processing product ${product_id}:`, err.message);
        throw new Error(`Error processing product ${product_id}: ${err.message}`);
      }
    };
    // --- END CORE PROCESSING LOGIC ---


    // Process products in chunks
    const productChunks = chunkArray(product_ids, CONCURRENCY_CHUNK_SIZE);
    let allSettledResults = [];

    for (const chunk of productChunks) {
      const promises = chunk.map(processProduct);
      const settledResults = await Promise.allSettled(promises);
      allSettledResults = allSettledResults.concat(settledResults);
      if (productChunks.indexOf(chunk) < productChunks.length - 1) {
        await new Promise((resolve) => setTimeout(resolve, BATCH_DELAY_MS));
      }
    }

    // Aggregate results
    const results = allSettledResults.map((result) => {
      if (result.status === "fulfilled") return result.value;
      const errorMessage = result.reason.message || "Unknown error occurred";
      const match = errorMessage.match(/Error processing product (\d+):/);
      const product_id = match ? match[1] : "Unknown ID";
      const errorDetail = errorMessage.replace(/Error processing product \d+: /, "");
      return { product_id, error: errorDetail };
    });

    const message = results
      .map((r) => (r.success ? r.success : `❌ Error processing product ${r.product_id}: ${r.error}`))
      .join("<br>");
    res.redirect(`/?message=${encodeURIComponent(message)}#create-bundles`);
});


app.post("/update-bundles", async (req, res) => {
  // 1. DYNAMIC CREDENTIAL RETRIEVAL
  const { shop, token, status } = getDynamicCredentials(req);
  if (status !== 'ok' && status !== 'fallback') {
      return res.status(401).send("Unauthorized");
  }
  
  const LOCAL_API_VERSION = "2025-01"; 
  let { product_ids, discount2 = 0, discount3 = 0 } = req.body;
  product_ids = Array.isArray(product_ids) ? product_ids : [product_ids];

  console.log("POST /update-bundles received:", { product_ids, discount2, discount3 });

  if (!product_ids || product_ids.length === 0) {
    return res.redirect(
      `/?message=${encodeURIComponent("❌ Error: At least one Product ID is required.")}#update-bundles`
    );
  }

  const results = [];

  // ✅ Helper: GraphQL API call (Using dynamic credentials)
  const shopifyGraphQLCallLocal = (query, variables = {}) => shopifyGraphQLCall(shop, token, query, variables);

  // ✅ Mutation for bulk variant update (Remains the same)
  const PRODUCT_VARIANTS_BULK_UPDATE_MUTATION = `
    mutation ProductVariantsBulkUpdate($productId: ID!, $variants: [ProductVariantsBulkInput!]!) {
      productVariantsBulkUpdate(productId: $productId, variants: $variants) {
        productVariants { id title price }
        userErrors { field message }
      }
    }
  `;

  // ✅ Process each product
  for (const product_id of product_ids) {
    try {
      // Step 1: Fetch product variants via GraphQL
      const productQuery = `
        query getProduct($id: ID!) {
          product(id: $id) {
            id
            title
            variants(first: 10) {
              edges {
                node {
                  id
                  title
                  price
                  selectedOptions { name value }
                }
              }
            }
          }
        }
      `;
      const productGid = `gid://shopify/Product/${product_id}`;
      // Updated call: Use local helper
      const data = await shopifyGraphQLCallLocal(productQuery, { id: productGid });
      const product = data?.product;
      if (!product) throw new Error(`Product not found (${product_id})`);

      const variants = product.variants.edges.map((e) => e.node);
      if (!variants.length) throw new Error("No variants found.");

      // Find base price (non-bundle or 1x)
      const baseVariant =
        variants.find((v) => {
          const opt = v.selectedOptions.find((o) => o.name === "Bundle");
          return !opt || !["1x", "2x", "3x"].includes(opt.value);
        }) || variants[0];

      const basePrice = parseFloat(baseVariant.price);
      console.log(`Base variant: ${baseVariant.title}, Base price: ${basePrice}`);

      // Step 2: Find 2x and 3x bundle variants
      const variant2x = variants.find((v) =>
        v.selectedOptions.some((o) => o.value === "2x")
      );
      const variant3x = variants.find((v) =>
        v.selectedOptions.some((o) => o.value === "3x")
      );

      // Step 3: Prepare updates
      const updates = [];
      if (variant2x) {
        updates.push({
          id: variant2x.id,
          price: (basePrice * 2 * (1 - discount2 / 100)).toFixed(2),
        });
      }
      if (variant3x) {
        updates.push({
          id: variant3x.id,
          price: (basePrice * 3 * (1 - discount3 / 100)).toFixed(2),
        });
      }

      if (!updates.length) {
        results.push({
          product_id,
          error: "No bundle variants (2x/3x) found to update.",
        });
        continue;
      }

      // Step 4: Bulk update prices via GraphQL
      // Updated call: Use local helper
      const updateResp = await shopifyGraphQLCallLocal(PRODUCT_VARIANTS_BULK_UPDATE_MUTATION, {
        productId: product.id,
        variants: updates,
      });

      const errors = updateResp.productVariantsBulkUpdate.userErrors || [];
      if (errors.length > 0) {
        throw new Error(`GraphQL update errors: ${JSON.stringify(errors)}`);
      }

      const updated = updateResp.productVariantsBulkUpdate.productVariants.map(
        (v) => `${v.title} → ${v.price}`
      );
      console.log(`✅ Updated: ${updated.join(", ")}`);

      results.push({
        product_id,
        success: `Updated variants (${updated.join(", ")})`,
      });
    } catch (err) {
      console.error(`❌ Error processing product ${product_id}:`, err.message);
      results.push({ product_id, error: err.message });
    }
  }

  const message = results
    .map((r) => (r.success ? `✅ ${r.success}` : `❌ ${r.error}`))
    .join("<br>");
  res.redirect(`/?message=${encodeURIComponent(message)}#update-bundles`);
});

// Sync bundle inventory route (manual)
app.post("/sync-bundle-inventory", async (req, res) => {
  const { product_id, variant_ids } = req.body;

  if (!product_id || !variant_ids) {
    console.error("Missing product_id or variant_ids");
    return res.redirect(`/?message=${encodeURIComponent("❌ Error: Product ID and variant IDs are required.")}`);
  }

  try {
    // Fetch product details
    const productQuery = `
      query getProduct($id: ID!) {
        product(id: $id) {
          id
          variants(first: 10) {
            edges {
              node {
                id
                selectedOptions {
                  name
                  value
                }
                sku
                inventoryItem {
                  id
                  inventoryLevels(first: 1) {
                    edges {
                      node {
                        quantities(names: ["available"]) {
                          name
                          quantity
                        }
                        location {
                          id
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const productGid = `gid://shopify/Product/${product_id}`;
    const data = await shopifyGraphQLCall(productQuery, { id: productGid });
    if (!data || !data.product) {
      throw new Error(`Invalid product response: ${JSON.stringify(data)}`);
    }
    const product = data.product;

    if (!product) {
      return res.redirect(`/?message=${encodeURIComponent("❌ Error: Product not found.")}`);
    }

    const variants = product.variants.edges.map(e => e.node);
    const baseVariant = variants.find(v => {
      const option1 = v.selectedOptions.find(opt => opt.name === "Bundle")?.value;
      return !["1x", "2x", "3x"].includes(option1);
    });
    if (!baseVariant) {
      return res.redirect(`/?message=${encodeURIComponent("❌ Error: No base variant found for product.")}`);
    }

    const baseInventoryLevel = baseVariant.inventoryItem.inventoryLevels.edges[0]?.node;
    const baseInventory = baseInventoryLevel?.quantities.find(q => q.name === "available")?.quantity || 0;
    const locationId = baseInventoryLevel?.location.id;
    console.log("Base Inventory for sync:", baseInventory, "Location ID:", locationId ? locationId.split('/').pop() : 'none');

    if (!locationId) {
      return res.redirect(`/?message=${encodeURIComponent("❌ Error: No location found for base variant inventory.")}`);
    }

    // Update bundle variant inventories
    const inventoryToSet = [];

    for (const [bundleType, variantIdNum] of Object.entries(variant_ids)) {
      const qty = parseInt(bundleType);
      const newInventory = Math.floor(baseInventory / qty);
      const variantGid = `gid://shopify/ProductVariant/${variantIdNum}`;
      const variant = variants.find(v => v.id === variantGid);
      if (!variant) continue;

      const inventoryItemId = variant.inventoryItem.id;

      inventoryToSet.push({
        inventoryItemId,
        locationId,
        quantity: newInventory >= 0 ? newInventory : 0
      });
    }

    if (inventoryToSet.length > 0) {
      const inventoryMutation = `
        mutation inventorySetQuantities($input: InventorySetQuantitiesInput!) {
          inventorySetQuantities(input: $input) {
            inventoryAdjustmentGroup {
              id
            }
            userErrors {
              field
              message
            }
          }
        }
      `;
      const input = {
        name: "available",
        reason: "correction",
        quantities: inventoryToSet.map(s => ({
          inventoryItemId: s.inventoryItemId,
          locationId: s.locationId,
          quantity: s.quantity
        }))
      };
      const inventoryData = await shopifyGraphQLCall(inventoryMutation, { input });
      if (inventoryData.inventorySetQuantities.userErrors.length > 0) {
        throw new Error(JSON.stringify(inventoryData.inventorySetQuantities.userErrors));
      }
      console.log("Bundle inventory synced successfully");
    }

    res.redirect(`/?message=${encodeURIComponent("✅ Bundle inventory synced successfully")}`);
  } catch (err) {
    console.error("Error syncing inventory:", err);
    res.redirect(`/?message=${encodeURIComponent(`❌ Error syncing inventory: ${err.message}`)}`);
  }
});

// ... (existing code up to app.post("/delete-bundles", ...) )
app.post("/delete-bundles", async (req, res) => {
  // 1. DYNAMIC CREDENTIAL RETRIEVAL
  const { shop, token, status } = getDynamicCredentials(req);
  if (status !== 'ok' && status !== 'fallback') {
      return res.status(401).send("Unauthorized");
  }

  const LOCAL_API_VERSION = "2025-01"; 
  const { product_id } = req.body;

  if (!product_id) {
    return res.redirect(
      `/?message=${encodeURIComponent("❌ Error: Product ID is required for deletion.")}#existing-bundles`
    );
  }

  // --- LOCAL DYNAMIC API HELPERS ---
  const shopifyGraphQLCallLocal = (query, variables = {}) => shopifyGraphQLCall(shop, token, query, variables);
  const shopifyApiCallLocal = (method, url, data = null) => shopifyApiCall(shop, token, method, url, data);
  // --- END LOCAL DYNAMIC API HELPERS ---

  try {
    // 1. Fetch all product variants using GraphQL for reliability
    const productGid = `gid://shopify/Product/${product_id}`;
    const productQuery = `
      query getProductVariants($id: ID!) {
        product(id: $id) {
          variants(first: 20) { 
            edges { 
              node { 
                id 
                selectedOptions { name value }
              } 
            } 
          }
        }
      }
    `;

    // Updated call: Use local helper
    const data = await shopifyGraphQLCallLocal(productQuery, { id: productGid });
    const variants = data?.product?.variants?.edges.map(e => e.node) || [];
    
    if (variants.length === 0) {
        throw new Error("GraphQL returned no variants for this product ID.");
    }

    // 2. Identify and delete bundle variants (1x, 2x, 3x) using REST
    const bundleVariantsToDelete = variants.filter(v => {
        const bundleOption = v.selectedOptions.find(o => o.name === "Bundle");
        return bundleOption && ["1x", "2x", "3x"].includes(bundleOption.value);
    });

    if (bundleVariantsToDelete.length === 0) {
        console.warn(`Product ${product_id}: No 1x/2x/3x bundle variants found to delete.`);
    }

    let deletedCount = 0;
    for (const variant of bundleVariantsToDelete) {
        const variantIdNum = variant.id.split("/").pop(); 
        // Note: The URL is now relative since the base domain is handled by the API helper
        const variantDeleteUrl = `/admin/api/${LOCAL_API_VERSION}/products/${product_id}/variants/${variantIdNum}.json`;
        
        try {
            // Updated call: Use local helper
            await shopifyApiCallLocal("delete", variantDeleteUrl);
            deletedCount++;
        } catch (err) {
            console.warn(`⚠️ Failed to delete variant ${variantIdNum} for ${product_id}: ${err.message}`);
        }
    }
    
    // 3. Update product options to remove 'Bundle' and reset to 'Title'
    const productUpdateUrl = `/admin/api/${LOCAL_API_VERSION}/products/${product_id}.json`;
    
    const updateData = {
        product: { 
            id: product_id, 
            options: [{ name: "Title" }] 
        },
    };
    // Updated call: Use local helper
    await shopifyApiCallLocal("put", productUpdateUrl, updateData);

    const message = `✅ Successfully deleted ${deletedCount} bundle variants and reverted options for product ${product_id}.`;
    console.log(message);
    res.redirect(`/?message=${encodeURIComponent(message)}#existing-bundles`);

  } catch (err) {
    console.error(`❌ Error deleting bundles for product ${product_id}:`, err.message);
    res.redirect(
      `/?message=${encodeURIComponent(`❌ Error deleting bundles for product ${product_id}: ${err.message}`)}#existing-bundles`
    );
  }
});
// ... (existing code continues from here)

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
