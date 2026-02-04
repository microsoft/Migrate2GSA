Similar to Convert-ZPA2EPA.ps1, we need to build Convert-ZIA2EIA.ps1 to import ZScaler Internet Access configuration and transform to Entra Internet Access configuration.

> SUPER DRAFT Version :) manually crafted, no AI involved.

## ZScaler Internet Access input configuration files

### url_filtering_policy.json
This file is the result of this API call https://help.zscaler.com/zia/url-filtering-policy#/urlFilteringRules-get
Schema:
``` json
{
  "id": 0,
  "name": "string",
  "order": 0,
  "protocols": [
    "SMRULEF_ZPA_BROKERS_RULE"
  ],
  "locations": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "groups": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "departments": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "users": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "urlCategories": [
    "ANY"
  ],
  "urlCategories2": [
    "ANY"
  ],
  "state": "DISABLED",
  "timeWindows": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "workloadGroups": [
    {
      "id": 0,
      "name": "string",
      "description": "string",
      "expressionJson": {
        "expressionContainers": [
          {
            "tagType": "ANY",
            "operator": "AND",
            "tagContainer": {
              "tags": [
                {
                  "key": "string",
                  "value": "string"
                }
              ],
              "operator": "AND"
            }
          }
        ]
      },
      "expression": "string",
      "lastModifiedTime": 0,
      "lastModifiedBy": {
        "id": 0,
        "name": "string",
        "externalId": "string",
        "extensions": {
          "additionalProp1": "string",
          "additionalProp2": "string",
          "additionalProp3": "string"
        }
      }
    }
  ],
  "rank": 0,
  "requestMethods": [
    "OPTIONS"
  ],
  "endUserNotificationUrl": "string",
  "overrideUsers": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "overrideGroups": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "blockOverride": false,
  "timeQuota": 0,
  "sizeQuota": 0,
  "description": "string",
  "locationGroups": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "labels": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "validityStartTime": 0,
  "validityEndTime": 0,
  "validityTimeZoneId": "string",
  "lastModifiedTime": 0,
  "lastModifiedBy": {
    "id": 0,
    "name": "string",
    "externalId": "string",
    "extensions": {
      "additionalProp1": "string",
      "additionalProp2": "string",
      "additionalProp3": "string"
    }
  },
  "enforceTimeValidity": true,
  "devices": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "deviceGroups": [
    {
      "id": 0,
      "name": "string",
      "externalId": "string",
      "extensions": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
      }
    }
  ],
  "deviceTrustLevels": [
    "ANY"
  ],
  "action": "BLOCK",
  "cbiProfile": {
    "id": "string",
    "name": "string",
    "url": "string",
    "defaultProfile": true
  },
  "ciparule": false
}
```

Key information to parse and filter:
- Name
- Order
- Groups, an array of the name attribute
- Users, parse all the users email addresses, only for users where deleted is not true. (log the ones skipped in debug mode). Here is an example:
    "users": [
      {
        "id": 74436938,
        "name": "Luke Skywalker (luke@contoso.com)",
      },
      {
        "id": 74436938,
        "name": "Kylo Ren (kylo@contoso.com)",
        "deleted": true
      }
    ],
- urlCategories
- state (only rules set to ENABLED, log the ones skipped)
- description
- action


### url_categories.json
This file is the result of this API call: https://help.zscaler.com/zia/url-categories#/urlCategories-get
Schema:
``` json
{
  "id": "ANY",
  "configuredName": "string",
  "superCategory": "ANY",
  "keywords": [
    "string"
  ],
  "keywordsRetainingParentCategory": [
    "string"
  ],
  "urls": [
    "string"
  ],
  "dbCategorizedUrls": [
    "string"
  ],
  "ipRanges": [
    "string"
  ],
  "ipRangesRetainingParentCategory": [
    "string"
  ],
  "customCategory": false,
  "scopes": [
    {
      "scopeGroupMemberEntities": [
        {
          "id": 0,
          "name": "string",
          "externalId": "string",
          "extensions": {
            "additionalProp1": "string",
            "additionalProp2": "string",
            "additionalProp3": "string"
          }
        }
      ],
      "Type": "ORGANIZATION",
      "ScopeEntities": [
        {
          "id": 0,
          "name": "string",
          "externalId": "string",
          "extensions": {
            "additionalProp1": "string",
            "additionalProp2": "string",
            "additionalProp3": "string"
          }
        }
      ]
    }
  ],
  "editable": false,
  "description": "string",
  "type": "URL_CATEGORY",
  "urlKeywordCounts": {
    "totalUrlCount": 0,
    "retainParentUrlCount": 0,
    "totalKeywordCount": 0,
    "retainParentKeywordCount": 0
  },
  "customUrlsCount": 0,
  "urlsRetainingParentCategoryCount": 0,
  "customIpRangesCount": 0,
  "ipRangesRetainingParentCategoryCount": 0
}
```
Key information to parse and filter:
- id
- type (only "URL_CATEGORY", filter others and log the skipped ones)
- customCategory
- configuredName
- urls
- dbCategorizedUrls
- description

## ZIA2EIA-CategoryMappings.json
Schema / example:
``` json
{
  "LastUpdated": "2025-10-09",
  "MappingData": [
    {
      "ZIACategory": "OTHER_ADULT_MATERIAL",
      "ZIADescription": "Sites that contain adult-oriented content not classified elsewhere.",
      "ExampleURLs": "www.adultfriendfinder.com, www.eroprofile.com",
      "GSACategory": "AdultContent",
      "MappingNotes": "Mapped based on semantic similarity"
    }
    ]
}
```
Load all mappings.


## Conversion

### url categories

#### custom categories ("customCategory": true)

- combine and deduplicate urls and dbCategorizedUrls
- split the list into urls (include a slash like www.domain.com/news), fqdns (www.domain.com) and ipAddresses
- for IP addresses, filter out the ones that are not strictly just an ip address, for example 100.100.100.100/somepath should be excluded, same for 100.100.100.100:80. In INFO log the fact that the url category had IP addresses that were skipped, not each IP address. In DEBUG log each entry being filtered out.
- group fqdn that share the same domain, for example "endor.org" and "moon.endor.org" should be grouped together.
- group urls that share the same domain, for example "endor.org/ewoks" and "moon.endor.org/forest" should be grouped together.
- Denormalize each custom category

Conversion output
File: Timestamp-EIA-WCF-Policies.csv
Fields:
WCFName = configuredName, fallback to id
Action = Allow / Block (to be updated as part of url filtering rule conversion)
Description = description
DestinationType = FQDN / URL / webCategory / ipAddress
Destinations = one group of FQDN, URL or ipAddress. Comma-separated. Each group should be below a limit of characters. Make the limit (destinationsMaxLength) configurable, default of 300 characters.
RuleName = FQDNs[x] where x is the number of the group type, same for URL and IPs


Example
This ZIA custom web category
  {
    "id": "CUSTOM_10",
    "configuredName": "Custom Web Cat",
    "urls": [
      "secure.okbiz.com",
      ".marketo.com",
      "facebook.com",
      "google.com/news",
      "secure.domain.com/notsosecure",
      ""
    ]
    ,
    "dbCategorizedUrls": [
      "secure.okbiz.com",
      ".marketo.com",
      "chat.remote.com",
      ".marketdesigner.com",
      "www.yahoo.com/finance",
      "secure.domain.com/supersecure"
    ],
    "Description": "some description",
    "customCategory": true,
    "editable": true,
    "type": "URL_CATEGORY",
    "val": 137
  }

becomes:
WCFName, Action, Description, DestinationType, Destinations, RuleName
"Custom Web Cat","", "some desription", "FQDN", ""secure.okbiz.com",".marketo.com","facebook.com","chat.remote.com",".marketdesigner.com"", "FQDN1"
"Custom Web Cat","", "some desription", "URL", ""secure.domain.com/notsosecure","www.yahoo.com/finance","secure.domain.com/supersecure"", "URLs1"





### url filtering rules
- url filtering rules can have: non custom url categories (ZIACategory), IP addresses, URLs and FQDNs. All these should be parsed and converted as per below.
- non custom url categories, we should look up each entry in the CategoryMappings ZIACategory, if we find a match get the GSACategory. Log in INFO if a GSACategory doesn't exist (null, blank). Group them and create an entry in the Web Categories. See example below.

- If the rule action is block, then update all the WCFNames (web content filtering policies) that are linked to the filtering rule Action to Block, same for Allow.
- If further url filtering rules also target the same WCFName and the WCFName has already been set to either Allow or Block by a previous reference, duplicate the WCFName, append -block or -allow to the name and set action as appropriate.
- Denormalize each url filtering rule
- If no users or groups are defined we should set EntraGroups to "All-IA-Users"


Conversion output:
File: Timestamp-EIA-SecurityProfiles.csv
Fields:
SPName = Name
Priority = Order*10
EntraGroups = Groups
EntraUsers = Users
WCFLinks = a comma-separated list of WCFName
Description = Description


Example url filtering rule with only non custom web categories:
``` json
{
    "id": 12345,
    "accessControl": "READ_WRITE",
    "name": "urlRule1",
    "order": 14,
    "urlCategories": [
      "OTHER_RELIGION",
      "NEWLY_REG_DOMAINS"
    ],
    "state": "ENABLED",
    "rank": 7,
    "action": "BLOCK"
  }
  ```
Example ZIA2EIA category mapping:
``` json
{[
  {
      "ZIACategory": "OTHER_RELIGION",
      "ZIADescription": "Other sites related to religion that is not classified in the defined categories.",
      "ExampleURLs": "stmarkstn.org, qcforjesus.com",
      "GSACategory": "Religion",
      "MappingNotes": "Mapped based on semantic similarity"
    },
      {
      "ZIACategory": "NEWLY_REG_DOMAINS",
      "ZIADescription": "Sites whose domains were created in the last 30 days and are currently not categorized by Zscaler. This category also includes domains that we encounter for the first time. Domains under this category are considered suspicious until they are categorized or better understood by Zscaler.",
      "ExampleURLs": null,
      "GSACategory": "NewDomains",
      "MappingNotes": "No direct mapping found"
    }
]
}

This should be converted to:
WCFName, Action, Description, DestinationType, Destinations, RuleName
"urlRule1-WebCategories-Block","Block","Converted from urlRule1 categories","webCategory",""Religion","NewDomains"","WebCategories1"