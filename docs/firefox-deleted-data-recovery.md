# How Firefox Tools Find Deleted Files - Simple Explanation

## What This Document Explains
This document explains in simple terms how the Firefox forensics tools work to find deleted browsing history and other data that users thought they had permanently removed.

## Why Firefox is Special for Forensics

Unlike Chrome or Safari, Firefox keeps multiple copies of your browsing data in different places. This makes it much easier to recover "deleted" information.

Think of it like this:
- **Chrome**: When you delete something, it's gone (like throwing paper in a shredder)
- **Firefox**: When you delete something, it's like putting it in a "maybe trash" folder that keeps multiple backups

## How Firefox Stores Your Data

### 1. The Main Database
**File**: `places.sqlite`
**What it contains**: Your current browsing history
**Think of it as**: Your main filing cabinet

### 2. Session Backups
**Folder**: `sessionstore-backups/`
**What it contains**: Compressed backups of your recent browsing sessions
**Think of it as**: Automatic backup copies that Firefox makes

### 3. WAL Files (Write-Ahead Log)
**File**: `places.sqlite-wal`
**What it contains**: Recent changes before they're saved to the main database
**Think of it as**: A "pending changes" file

### 4. Journal Files
**File**: `places.sqlite-journal`
**What it contains**: Transaction logs of database changes
**Think of it as**: A log of what was changed and when

## How the Tools Find Deleted Data

### Method 1: Session File Recovery
**What it does**: Looks in Firefox's automatic backup files

**How it works**:
1. Firefox automatically creates compressed backup files of your browsing sessions
2. These files are stored in the `sessionstore-backups/` folder
3. Even when you "delete" history, these backup files still contain the old data
4. The tool decompresses these files and extracts the URLs and page titles

**Real-world analogy**: It's like finding old photos in a backup folder on your computer, even after you deleted them from your main photo album.

**Why it works**: Firefox keeps these backups in case the browser crashes, so you don't lose your open tabs.

### Method 2: WAL File Recovery
**What it does**: Looks for recently deleted data in "pending changes" files

**How it works**:
1. When you browse the web, Firefox writes changes to a WAL (Write-Ahead Log) file first
2. Later, it moves these changes to the main database
3. If you delete history quickly, the WAL file might still contain the deleted data
4. The tool searches through the WAL file for URL patterns

**Real-world analogy**: It's like checking your "draft" folder for emails you thought you deleted.

**Why it works**: Firefox doesn't immediately remove data from WAL files - it just marks it for deletion.

### Method 3: Database Free Space Analysis
**What it does**: Searches for deleted data in unused database space

**How it works**:
1. When you delete data from a database, it's not immediately overwritten
2. The space is just marked as "available for new data"
3. The tool searches through this "free space" for URL patterns
4. It also looks for page titles near the URLs

**Real-world analogy**: It's like finding old writing on a piece of paper that was "erased" but the pencil marks are still faintly visible.

**Why it works**: Database systems don't immediately overwrite deleted data - they just mark the space as available.

### Method 4: Cookie Analysis
**What it does**: Reconstructs visited websites from cookie data

**How it works**:
1. Cookies are small files websites store on your computer
2. Even when you delete browsing history, cookies often remain
3. The tool looks at all cookie hostnames (like "google.com", "facebook.com")
4. It creates a list of websites you probably visited based on the cookies

**Real-world analogy**: It's like finding business cards in your wallet and figuring out where you've been based on the companies.

**Why it works**: Cookies are designed to persist longer than browsing history, so they often outlast deleted history.

## The "Deleting More Shows Less" Phenomenon

This is a key forensic principle that confuses many people:

### What Happens When You Delete History

**Normal Deletion**:
1. You delete some history
2. Database marks records as "deleted" but keeps the data
3. Space is marked as "free" but data is still there
4. **Recovery potential**: HIGH

**Heavy Deletion**:
1. You delete a lot of history at once
2. Database thinks "this person wants to clean up"
3. Database runs a "VACUUM" operation to reorganize itself
4. VACUUM overwrites the "free space" with zeros
5. **Recovery potential**: LOW

### Why This Happens
- **Light deletion**: Database thinks "just mark as deleted, keep the data"
- **Heavy deletion**: Database thinks "user wants to clean up, let's actually remove the data"

**💡 Key Insight**: The more someone tries to hide their tracks, the more evidence they actually destroy!

## Step-by-Step: How the Tools Work

### Step 1: Find Firefox Profile
```
1. Look for Firefox profile folder
2. Check if places.sqlite exists
3. Find sessionstore-backups folder
```

### Step 2: Session File Recovery
```
1. List all .jsonlz4 files in sessionstore-backups/
2. For each file:
   a. Read the file header
   b. Decompress using LZ4 algorithm
   c. Parse the JSON data
   d. Extract URLs and titles from windows/tabs
   e. Filter out invalid URLs
```

### Step 3: WAL File Recovery
```
1. Check if places.sqlite-wal exists
2. Read the entire WAL file as binary data
3. Search for URL patterns using regex
4. Extract any URLs found
```

### Step 4: Free Space Analysis
```
1. Read the entire places.sqlite database as binary
2. Search for URL patterns throughout the file
3. Look for page titles near URLs
4. Create recovery entries for found data
```

### Step 5: Cookie Analysis
```
1. Open cookies.sqlite database
2. Get all unique hostnames from cookies
3. Reconstruct likely URLs from hostnames
4. Create entries for sites with cookies but no history
```

## What the Tools Find

### Types of Recovered Data
- **URLs**: Website addresses that were visited
- **Page Titles**: The titles of web pages
- **Timestamps**: When pages were accessed (if available)
- **Recovery Method**: How the data was found

### Recovery Status Levels
1. **Standard**: Normal browser data (not deleted)
2. **Session Backup**: Found in Firefox session files
3. **WAL Recovery**: Found in Write-Ahead Log files
4. **Free Space**: Found in unallocated database space
5. **Cookie Analysis**: Reconstructed from cookie data

## Why This Matters

### For Investigators
- **Timeline Reconstruction**: Shows what someone was doing even after they "cleaned up"
- **Evidence Preservation**: Finds data that suspects thought was deleted
- **Pattern Analysis**: Shows browsing patterns and interests

### For Students
- **Digital Forensics**: Demonstrates how deleted data can be recovered
- **Browser Behavior**: Shows how browsers actually store data
- **Data Persistence**: Explains why "deleted" doesn't always mean "gone"

## Limitations

### What the Tools CAN'T Find
- **Encrypted Data**: If Firefox data is encrypted, it can't be read
- **Cloud-Synced Data**: Only looks at local files, not cloud backups
- **Private Browsing**: Limited data from private/incognito mode
- **Completely Overwritten Data**: If database was vacuumed, data is gone

### When Recovery Works Best
- **Recent Deletions**: Data deleted recently is more likely to be recoverable
- **Light Usage**: Less database activity means more recoverable data
- **Multiple Browsers**: Cross-browser analysis provides more evidence

## Real-World Example

### Scenario: Someone Tries to Hide Their Tracks
1. **User visits suspicious websites**
2. **User deletes browsing history** (thinks it's gone)
3. **Forensic tool runs**:
   - Finds deleted URLs in session backups
   - Recovers page titles from WAL files
   - Reconstructs timeline from cookie data
4. **Result**: Complete timeline of "deleted" activity

### What the Report Shows
```
RECOVERED DELETED HISTORY:
- URL: suspicious-site.com
- Title: "How to Hide Your Tracks"
- Recovery Method: Session Backup
- Timestamp: 2024-01-15 14:30:00
- Status: Successfully recovered from Firefox session file
```

## Summary

The Firefox forensics tools work by taking advantage of how Firefox stores data in multiple places. Even when users think they've deleted their browsing history, the tools can often recover it from:

1. **Session backup files** (automatic backups)
2. **WAL files** (pending changes)
3. **Database free space** (marked as deleted but not overwritten)
4. **Cookie data** (persistent tracking information)

This makes Firefox particularly valuable for digital forensics investigations, as it often provides more recoverable evidence than other browsers.

The key insight is that "deleted" in digital forensics often means "marked for deletion" rather than "permanently removed" - and the tools take advantage of this to recover evidence that suspects thought was gone forever.
