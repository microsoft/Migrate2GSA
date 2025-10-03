# Specification: Implement Pagination for All ZPA API Calls

**Date:** October 3, 2025  
**Status:** Approved  
**Script:** Export-ZPAConfig.ps1

## Overview

Implement consistent pagination support across all ZPA API endpoints in the Export-ZPAConfig.ps1 script, following the pattern established for SCIM groups but extending it to all API calls.

## Background

Currently, only the `Get-ZPAScimGroups` function implements pagination. All other ZPA API endpoints make single requests without pagination, which may result in incomplete data retrieval for large datasets. According to ZPA documentation, all API endpoints support pagination using `page` and `pageSize` query parameters.

**Reference Documentation:**
- [ZPA Policy Management API](https://help.zscaler.com/zpa/policy-management)
- [ZPA Application Segment Management API](https://help.zscaler.com/zpa/application-segment-management#/mgmtconfig/v1/admin/customers/{customerId}/application-get)

## Requirements

### 1. Always-On Pagination
- Pagination must be enabled by default for all API calls
- No option to disable (always-on approach)

### 2. Page Size Configuration
- Default page size: **20** (per ZPA documentation)
- Must be configurable at script level via parameter
- Can be overridden per-endpoint if needed

### 3. Rate Limiting
- Default delay between page requests: **1 second**
- Must be configurable at script level via parameter
- Applied after each page request except the last

### 4. Progress Reporting
- Display: "Page X of Y" for each page retrieved
- Display: Total items retrieved (running count)
- Verify: Retrieved count matches API's total count
- Format: "Page X of Y - Retrieved Z items"
- Final: "Retrieved N of M total items" (validation)

### 5. Consistent Implementation
- Use Option A: Centralized pagination in `Invoke-ZPAApi`
- Minimal changes to individual Get-ZPA* functions
- Refactor `Get-ZPAScimGroups` to use common pagination logic

## Implementation Plan

### Phase 1: Core Pagination Function

**Update `Invoke-ZPAApi` function:**

#### New Parameters
```powershell
[Parameter(Mandatory = $true)]
[string]$Endpoint

[Parameter(Mandatory = $false)]
[int]$PageSize = 20

[Parameter(Mandatory = $false)]
[int]$PageDelay = 1
```

#### Pagination Logic
1. **URL Construction:**
   - Check if endpoint already contains query parameters (`?` present)
   - If yes: append `&page=X&pageSize=Y`
   - If no: append `?page=X&pageSize=Y`

2. **First Request:**
   - Make initial API call with `page=1&pageSize=$PageSize`
   - Check response structure to detect pagination support

3. **Response Detection:**
   - **Paginated endpoint:** Response has `list` array and `totalPages` property
   - **Non-paginated endpoint:** Response is array or single object
   - For non-paginated: return response as-is (no pagination needed)

4. **Page Loop (for paginated endpoints):**
   - Loop from page 1 to `totalPages` (from API response)
   - Display progress: "Page X of Y - Retrieved Z items"
   - Accumulate all items from `list` property
   - Apply `$PageDelay` seconds delay between requests
   - Track total items retrieved

5. **Validation:**
   - Compare retrieved count vs API's `totalCount` (if provided)
   - Log warning if counts don't match
   - Display: "Retrieved N of M total items"

6. **Return Format:**
   ```powershell
   @{
       list = $allItems
       totalCount = $totalItemsRetrieved
       totalPages = $totalPages
   }
   ```

#### Error Handling
- Log warning for failed pages
- Retry failed page once before skipping
- Continue to next page on persistent failure
- Track and report failed pages at end
- Don't fail entire backup due to single page failure

#### Safety Limits
- Maximum pages: 1000 (safety limit)
- Log warning if limit reached
- Prevents infinite loops

### Phase 2: Update Individual Functions (Option A)

**Minimal changes to existing functions:**

All Get-ZPA* functions continue to call `Invoke-ZPAApi` with just the endpoint:
- `Get-ZPAApplicationSegments`
- `Get-ZPASegmentGroups`
- `Get-ZPAServerGroups`
- `Get-ZPAAppConnectors`
- `Get-ZPAConnectorGroups`
- `Get-ZPAAccessPolicies`
- `Get-ZPAClientForwardingPolicy`
- `Get-ZPAServiceEdges`
- `Get-ZPAServiceEdgeGroups`
- `Get-ZPAIdpControllers`
- `Get-ZPAMachineGroups`

**Optional Enhancement:**
- Functions can override `PageSize` if needed
- Example: `Invoke-ZPAApi -Endpoint "..." -PageSize 50`

### Phase 3: Refactor SCIM Groups

**Simplify `Get-ZPAScimGroups` function:**

**Before:** Manual pagination loop with duplicate code  
**After:** Use `Invoke-ZPAApi` with automatic pagination

Changes:
1. Remove manual pagination loop code
2. Call `Invoke-ZPAApi` with per-IDP endpoint
3. Let `Invoke-ZPAApi` handle pagination automatically
4. Keep IDP iteration logic in `Get-AllZPAScimGroups`

### Phase 4: Script-Level Configuration

**Add new script parameters:**

```powershell
[Parameter(Mandatory = $false)]
[int]$PageSize = 20

[Parameter(Mandatory = $false)]
[int]$PageDelay = 1
```

**Pass to functions:**
- Pass `$PageSize` and `$PageDelay` to `Invoke-ZPAApi` calls
- Use script-level variables for consistency

### Phase 5: Enhanced Logging & Validation

**Logging Improvements:**
1. Show pagination progress for each endpoint
2. Display page-by-page progress
3. Log total items from API vs items retrieved
4. Warn if counts don't match
5. Maintain existing verbose logging style
6. Use consistent color coding:
   - Gray: Debug/verbose information
   - Green: Success messages
   - Yellow: Warnings
   - Red: Errors

## Technical Specifications

### API Pagination Parameters
- `page`: 1-based page number (starts at 1)
- `pageSize`: Number of items per page (default: 20)

### Response Structure (Paginated Endpoints)
```json
{
  "list": [ /* array of items */ ],
  "totalPages": 10,
  "totalCount": 195
}
```

### Response Structure (Non-Paginated Endpoints)
- May return array directly: `[ /* items */ ]`
- May return single object: `{ /* properties */ }`

### URL Construction Examples
```
# No existing query params
/mgmtconfig/v1/admin/customers/123/application
→ /mgmtconfig/v1/admin/customers/123/application?page=1&pageSize=20

# Existing query params
/mgmtconfig/v1/admin/customers/123/application?status=active
→ /mgmtconfig/v1/admin/customers/123/application?status=active&page=1&pageSize=20
```

## Testing Strategy

1. **Small Page Size Test:**
   - Set `PageSize` to 5
   - Verify pagination loops correctly
   - Confirm all items retrieved

2. **Count Validation:**
   - Verify retrieved count matches API's `totalCount`
   - Test with various dataset sizes

3. **Endpoint Compatibility:**
   - Test each endpoint type
   - Verify paginated and non-paginated endpoints both work

4. **SCIM Groups Regression:**
   - Verify SCIM groups still work after refactoring
   - Test with multiple IDPs

5. **Rate Limiting:**
   - Verify delays are applied correctly
   - Ensure no API rate limit errors

6. **Error Scenarios:**
   - Test page failure handling
   - Verify retry logic
   - Confirm backup continues after failed page

## Success Criteria

1. ✅ All API endpoints support pagination automatically
2. ✅ Page size configurable (default: 20)
3. ✅ Rate limiting configurable (default: 1 second)
4. ✅ Progress reporting shows "Page X of Y" and item counts
5. ✅ Retrieved counts validated against API totals
6. ✅ `Get-ZPAScimGroups` refactored to use common logic
7. ✅ No breaking changes to existing functionality
8. ✅ Improved logging and error handling
9. ✅ Code duplication eliminated

## Benefits

1. **Completeness:** Ensures all data is retrieved, even for large datasets
2. **Consistency:** Same pagination logic across all endpoints
3. **Maintainability:** Single implementation to maintain
4. **Visibility:** Better progress reporting and validation
5. **Reliability:** Improved error handling and retry logic
6. **Performance:** Configurable page size and delays
7. **Safety:** Maximum page limit prevents infinite loops

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| API rate limiting | Configurable delays between requests (default: 1 second) |
| Incomplete data retrieval | Count validation and warnings |
| Increased execution time | Parallelization consideration for future enhancement |
| Breaking changes | Maintain backward-compatible response format |
| Infinite loops | Maximum page limit (1000 pages) |

## Future Enhancements

1. Parallel page requests (if API supports)
2. Adaptive delay based on API response headers
3. Resume capability for interrupted backups
4. Per-endpoint page size configuration
5. Exponential backoff on rate limit errors

## References

- ZPA API Documentation: https://help.zscaler.com/zpa
- Existing SCIM Groups Implementation: `Get-ZPAScimGroups` function
- PowerShell Best Practices: Microsoft guidelines
