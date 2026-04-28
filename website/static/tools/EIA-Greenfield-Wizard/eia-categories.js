/**
 * EIA Greenfield Wizard — Web Category Data
 *
 * Source: Specs/Tools/EntraInternetAccess-WebCategories.csv
 * These are the Microsoft Entra Internet Access (EIA) predefined web categories.
 * The `name` field is the PascalCase identifier used in the Graph API and CSV files.
 * The `displayName` field is the human-readable label shown in the UI.
 * The `group` field is a UI-only grouping for the category picker (not an EIA concept).
 *
 * Last synced from source CSV: 2026-04-03
 * Total categories: 69
 */

const EIA_CATEGORIES = [

  // ── Security & Risk ─────────────────────────────────────────────────────────
  { name: "ChildAbuseImages",             displayName: "Child Abuse Images",              group: "Security & Risk" },
  { name: "CriminalActivity",             displayName: "Criminal Activity",               group: "Security & Risk" },
  { name: "Hacking",                      displayName: "Hacking",                         group: "Security & Risk" },
  { name: "HateAndIntolerance",           displayName: "Hate And Intolerance",            group: "Security & Risk" },
  { name: "IllegalDrug",                  displayName: "Illegal Drug",                    group: "Security & Risk" },
  { name: "IllegalSoftware",              displayName: "Illegal Software",                group: "Security & Risk" },
  { name: "Marijuana",                    displayName: "Marijuana",                       group: "Security & Risk" },
  { name: "SelfHarm",                     displayName: "Self Harm",                       group: "Security & Risk" },
  { name: "Violence",                     displayName: "Violence",                        group: "Security & Risk" },
  { name: "Weapons",                      displayName: "Weapons",                         group: "Security & Risk" },
  { name: "Tasteless",                    displayName: "Tasteless",                       group: "Security & Risk" },
  { name: "CryptocurrencyMining",         displayName: "Cryptocurrency Mining",           group: "Security & Risk" },
  { name: "Cheating",                     displayName: "Cheating",                        group: "Security & Risk" },
  { name: "Cults",                        displayName: "Cults",                           group: "Security & Risk" },

  // ── Adult Content ────────────────────────────────────────────────────────────
  { name: "PornographyAndSexuallyExplicit", displayName: "Pornography And Sexually Explicit", group: "Adult Content" },
  { name: "Nudity",                        displayName: "Nudity",                         group: "Adult Content" },
  { name: "LingerieAndSwimsuits",          displayName: "Lingerie And Swimsuits",         group: "Adult Content" },
  { name: "SexEducation",                  displayName: "Sex Education",                  group: "Adult Content" },
  { name: "DatingAndPersonals",            displayName: "Dating And Personals",           group: "Adult Content" },
  { name: "AlcoholAndTobacco",             displayName: "Alcohol And Tobacco",            group: "Adult Content" },
  { name: "Gambling",                      displayName: "Gambling",                       group: "Adult Content" },

  // ── Social & Communication ────────────────────────────────────────────────────
  { name: "Chat",                         displayName: "Chat",                            group: "Social & Communication" },
  { name: "InstantMessaging",             displayName: "Instant Messaging",               group: "Social & Communication" },
  { name: "SocialNetworking",             displayName: "Social Networking",               group: "Social & Communication" },
  { name: "WebBasedEmail",                displayName: "Web Based Email",                 group: "Social & Communication" },
  { name: "ForumsAndNewsgroups",          displayName: "Forums And Newsgroups",           group: "Social & Communication" },
  { name: "PersonalSites",               displayName: "Personal Sites",                  group: "Social & Communication" },
  { name: "ProfessionalNetworking",       displayName: "Professional Networking",         group: "Social & Communication" },
  { name: "WebMeetings",                  displayName: "Web Meetings",                    group: "Social & Communication" },
  { name: "ImageSharing",                 displayName: "Image Sharing",                   group: "Social & Communication" },
  { name: "RemoteAccess",                 displayName: "Remote Access",                   group: "Social & Communication" },

  // ── Entertainment & Leisure ───────────────────────────────────────────────────
  { name: "Entertainment",               displayName: "Entertainment",                   group: "Entertainment & Leisure" },
  { name: "Games",                       displayName: "Games",                           group: "Entertainment & Leisure" },
  { name: "Arts",                        displayName: "Arts",                            group: "Entertainment & Leisure" },
  { name: "FashionAndBeauty",            displayName: "Fashion And Beauty",              group: "Entertainment & Leisure" },
  { name: "LeisureAndRecreation",        displayName: "Leisure And Recreation",          group: "Entertainment & Leisure" },
  { name: "NatureAndConservation",       displayName: "Nature And Conservation",         group: "Entertainment & Leisure" },
  { name: "RestaurantsAndDining",        displayName: "Restaurants And Dining",          group: "Entertainment & Leisure" },
  { name: "Sports",                      displayName: "Sports",                          group: "Entertainment & Leisure" },
  { name: "Travel",                      displayName: "Travel",                          group: "Entertainment & Leisure" },
  { name: "Shopping",                    displayName: "Shopping",                        group: "Entertainment & Leisure" },
  { name: "StreamingMediaAndDownloads",  displayName: "Streaming Media And Downloads",  group: "Entertainment & Leisure" },

  // ── Productivity & Business ───────────────────────────────────────────────────
  { name: "Business",                    displayName: "Business",                        group: "Productivity & Business" },
  { name: "CodeRepositories",            displayName: "Code Repositories",               group: "Productivity & Business" },
  { name: "ComputersAndTechnology",      displayName: "Computers And Technology",        group: "Productivity & Business" },
  { name: "Education",                   displayName: "Education",                       group: "Productivity & Business" },
  { name: "Finance",                     displayName: "Finance",                         group: "Productivity & Business" },
  { name: "Government",                  displayName: "Government",                      group: "Productivity & Business" },
  { name: "HealthAndMedicine",           displayName: "Health And Medicine",             group: "Productivity & Business" },
  { name: "JobSearch",                   displayName: "Job Search",                      group: "Productivity & Business" },
  { name: "News",                        displayName: "News",                            group: "Productivity & Business" },
  { name: "NonProfitsAndNgos",           displayName: "Non Profits And NGOs",            group: "Productivity & Business" },
  { name: "SearchEnginesAndPortals",     displayName: "Search Engines And Portals",      group: "Productivity & Business" },
  { name: "Translators",                 displayName: "Translators",                     group: "Productivity & Business" },
  { name: "WebRepositoryAndStorage",     displayName: "Web Repository And Storage",      group: "Productivity & Business" },
  { name: "DownloadSites",              displayName: "Download Sites",                  group: "Productivity & Business" },
  { name: "HostedPaymentGateways",       displayName: "Hosted Payment Gateways",         group: "Productivity & Business" },
  { name: "RealEstate",                  displayName: "Real Estate",                     group: "Productivity & Business" },
  { name: "Religion",                    displayName: "Religion",                        group: "Productivity & Business" },
  { name: "Transportation",              displayName: "Transportation",                  group: "Productivity & Business" },
  { name: "PoliticsAndLaw",              displayName: "Politics And Law",                group: "Productivity & Business" },
  { name: "ArtificialIntelligence",      displayName: "Artificial Intelligence",         group: "Productivity & Business" },

  // ── Infrastructure & Uncategorized ────────────────────────────────────────────
  { name: "PrivateIPAddresses",          displayName: "Private IP Addresses",            group: "Infrastructure" },
  { name: "AdvertisementsAndPopUps",     displayName: "Advertisements And Pop Ups",      group: "Infrastructure" },
  { name: "ParkedDomains",              displayName: "Parked Domains",                  group: "Infrastructure" },
  { name: "NewlyRegisteredDomains",      displayName: "Newly Registered Domains",        group: "Infrastructure" },
  { name: "Uncategorized",              displayName: "Uncategorized",                   group: "Infrastructure" },
  { name: "PeerToPeer",                  displayName: "Peer To Peer",                    group: "Infrastructure" },
  { name: "General",                     displayName: "General",                         group: "Infrastructure" },

];

// Helper: all unique group names in display order
const EIA_CATEGORY_GROUPS = [...new Set(EIA_CATEGORIES.map(c => c.group))];

// Helper: get categories for a given group
function getCategoriesByGroup(group) {
  return EIA_CATEGORIES.filter(c => c.group === group);
}

// Helper: get all category names except the ones provided (for "Block all except" model)
function getAllCategoriesExcept(excludedNames) {
  return EIA_CATEGORIES
    .filter(c => !excludedNames.includes(c.name))
    .map(c => c.name);
}
