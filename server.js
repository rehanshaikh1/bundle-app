import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import Bottleneck from "bottleneck";
import cors from "cors"; 
import crypto from 'crypto'; 
import querystring from 'querystring'; 
import cookieParser from 'cookie-parser'; 

dotenv.config();
const app = express();

// --- Configuration Constants (Read from .env) ---
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY; 
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET; 
const HOST = process.env.HOST; 
const SCOPES = 'read_products, write_products, read_inventory, write_inventory, read_orders';
const API_VERSION = "2025-10";

// --- Multi-Store Session/Token Management (Placeholder) ---
const shopsStore = {}; 

// --- Metafield Constants ---
const VISITOR_NAMESPACE = "bundle";
const VISITOR_KEY = "daily_visits"; 
const VISITOR_TYPE = "json"; 
const LEGACY_VISITOR_KEY = "visitors";


// --- CORS Configuration ---
const allowedOrigins = [
  'https://velonia.si',                       
  'https://www.velonia.si',                  
  'https://s0jd0m-rg.myshopify.com',
  process.env.HOST, 
]; 
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: 'GET,POST,PUT,DELETE',
  allowedHeaders: 'Content-Type,Authorization',
  credentials: true
};

app.use(cors(corsOptions));
app.use(cookieParser());

// Configure Bottleneck for rate limiting
const limiter = new Bottleneck({
  minTime: 500,
  maxConcurrent: 1
});

// Wrap axios methods with limiter
const limitedAxiosGet = limiter.wrap(axios.get);
const limitedAxiosPost = limiter.wrap(axios.post);
const limitedAxiosPut = limiter.wrap(axios.put);
const limitedAxiosDelete = limiter.wrap(axios.delete);

// --- DYNAMIC CREDENTIAL RETRIEVAL ---
const getDynamicCredentials = (req) => {
    const shop = req.query.shop || req.body.shop;
    const tokenData = shop ? shopsStore[shop] : null;

    if (tokenData && tokenData.accessToken) {
        return { shop: shop, token: tokenData.accessToken, status: 'ok' };
    }

    // Fallback for Local Development (If no session, use .env for one shop)
    if (process.env.SHOP && process.env.TOKEN) {
        shopsStore[process.env.SHOP] = { accessToken: process.env.TOKEN };
        return { shop: process.env.SHOP, token: process.env.TOKEN, status: 'fallback' };
    }
    
    return { shop: shop || null, token: null, status: 'unauthorized' };
};


// --- DYNAMIC API HELPERS ---

// Helper function for Shopify REST API calls
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
// --- END DYNAMIC API HELPERS ---


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.set("view engine", "ejs");
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "ALLOWALL");
  next();
});

// --- OAUTH FLOW IMPLEMENTATION ---

app.get('/shopify/install', (req, res) => {
    const shop = req.query.shop;
    if (!shop) {
        return res.status(400).send('Missing shop parameter');
    }

    const state = crypto.randomBytes(16).toString('hex');
    const redirectUri = `${HOST}/shopify/callback`;
    const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SCOPES}&state=${state}&redirect_uri=${redirectUri}`;

    res.cookie('state', state, { httpOnly: true, secure: true }); 
    res.redirect(installUrl);
});

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


// --- GRAPHQL MUTATIONS (Used by multiple routes) ---

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


// --- DATA FETCHING & AGGREGATION LOGIC ---

const BUNDLE_VARIANT_SALES_QUERY = (variantIds, dateFilter = "") => {
    // Correctly escape and format IDs for Shopify's query string filter
    const numericVariantIds = variantIds.map(id => id.split('/').pop());
    const idFilter = numericVariantIds.join(' OR ');
    const combinedQuery = `line_item_variant_ids:(${idFilter})${dateFilter ? ` AND ${dateFilter}` : ''}`;

    return `
      query GetVariantSales($after: String) {
        orders(query: "${combinedQuery}", first: 250, after: $after) {
          edges {
            node {
              lineItems(first: 250) {
                edges {
                  node {
                    variant {
                      id
                    }
                    quantity
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
};


async function fetchAndAggregateSales(shopDomain, accessToken, variantGids, skuToGidMap, dateFilter = "") {
    if (variantGids.length === 0) return new Map();

    const finalGidSalesMap = new Map();
    const allBundleSkus = new Set(skuToGidMap.keys());
    
    const CHUNK_SIZE = 50; 
    const chunks = [];
    for (let i = 0; i < variantGids.length; i += CHUNK_SIZE) {
        chunks.push(variantGids.slice(i, i + CHUNK_SIZE));
    }
    
    for (const chunk of chunks) {
        let chunkCursor = null;
        let chunkHasNextPage = true;
        let pageCount = 0;
        const MAX_PAGES = 10; 

        while (chunkHasNextPage && pageCount < MAX_PAGES) { 
            const query = BUNDLE_VARIANT_SALES_QUERY(chunk, dateFilter);
            
            const data = await shopifyGraphQLCall(shopDomain, accessToken, query, { cursor: chunkCursor }); 
            
            const orders = data?.orders?.edges || []; 
            pageCount++;

            orders.forEach(orderEdge => { 
                if (!orderEdge.node.createdAt) return;

                orderEdge.node.lineItems.edges.forEach(lineItemEdge => { 
                    const variantId = lineItemEdge.node.variant?.id;
                    const quantity = lineItemEdge.node.quantity;
                    
                    if (variantId && chunk.includes(variantId)) {
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
                // Filter: check if ANY variant has the bundle option value.
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
            
        // 💡 UPDATED CALL: Pass dynamic credentials
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
async function fetchData(shopDomain, accessToken) {
    return fetchProductsAndBundles(shopDomain, accessToken); 
}


async function fetchBundleMappings(shopDomain, accessToken) {
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
      // 💡 UPDATED CALL: Pass dynamic credentials
      const data = await shopifyGraphQLCall(shopDomain, accessToken, query, { first: 250, after: cursor });
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
// --- Metafield Constants (Ensure these match your created metafield) ---
const VISITOR_NAMESPACE = "bundle";
const VISITOR_KEY = "daily_visits"; 
const VISITOR_TYPE = "json"; 
const LEGACY_VISITOR_KEY = "visitors";


// 💡 FINAL GRAPHQL FUNCTION: Uses GraphQL for persistence and relies on shopifyGraphQLCall
app.post("/track-bundle-visit", async (req, res) => {
  const { shop, token, status } = getDynamicCredentials(req);
  if (status !== 'ok' && status !== 'fallback') {
      return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  const { product_id } = req.body;
  const productGid = `gid://shopify/Product/${product_id}`;
  const todayDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

  if (!product_id) {
    return res.status(400).json({ success: false, message: "Product ID required." });
  }

  const shopifyGraphQLCallLocal = (query, variables = {}) => shopifyGraphQLCall(shop, token, query, variables);

  try {
    // 1. FETCH: Retrieve the existing JSON metafield (and legacy total)
    const fetchResponse = await shopifyGraphQLCallLocal(VISITORS_FETCH_QUERY, { id: productGid });
    
    const metafieldData = fetchResponse?.product;
    const jsonMetafield = metafieldData?.metafield;
    
    let dailyCounts = {}; 
    let totalVisitors = 0;

    // A. Load existing daily data
    if (jsonMetafield && jsonMetafield.value) {
        try {
            dailyCounts = JSON.parse(jsonMetafield.value);
            totalVisitors = Object.values(dailyCounts).reduce((sum, count) => sum + count, 0);
        } catch (e) {
            console.warn(`Could not parse JSON for ${product_id}: ${jsonMetafield.value}. Initializing new map.`);
        }
    } 
    
    // B. Handle initialization/legacy migration (Optional)
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

    const updateResponse = await shopifyGraphQLCallLocal(VISITORS_UPDATE_MUTATION, variables);
    
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
