```markdown
# Enterprise OSINT Image Intelligence Collector

This tool monitors a folder for new or modified image files, extracts rich intelligence (metadata, GPS coordinates, OCR text, faces), performs reverse geocoding, logs everything, and detects file tampering. It is designed for production environments with features like circuit breakers, structured logging, health checks, and metrics.

## Features

- **Folder monitoring** – watches a directory (recursively) for images (`.jpg`, `.jpeg`, `.png`, `.tiff`, `.bmp`).
- **Metadata extraction** – full EXIF dump, plus structured fields (GPS, datetime, camera, software, dimensions, orientation).
- **Reverse geocoding** – converts GPS coordinates to addresses using OpenStreetMap Nominatim, with:
  - Persistent SQLite cache
  - Exponential backoff and retries
  - Circuit breaker to prevent repeated failures
- **OCR** – extracts visible text using Tesseract with preprocessing (grayscale + thresholding).
- **Face detection** – optional, using OpenCV Haar cascades.
- **Tamper detection** – SHA‑256 hash comparison; detects modifications and increments a counter.
- **Multithreading** – configurable worker pool to process multiple images concurrently.
- **Outputs**:
  - JSON file per image with all extracted data.
  - CSV summary with key fields.
  - SQLite database for querying and caching.
- **Production‑ready**:
  - Structured logging with rotation.
  - Configuration via YAML, environment variables, and CLI.
  - Health checks (database, worker status).
  - Metrics (processed count, errors, queue depth).
  - Graceful shutdown (SIGINT/SIGTERM).

## Prerequisites

- **Python 3.8+**
- **Tesseract OCR** (system dependency) – install via:
  - Windows: [UB‑Mannheim installer](https://github.com/UB-Mannheim/tesseract/wiki)
  - macOS: `brew install tesseract`
  - Linux: `sudo apt install tesseract-ocr`
- Python packages (see `requirements.txt` below)

## Installation

1. **Clone or download** the script (single file: `osint_image_collector.py`).

2. **Install Python dependencies**:
   ```bash
   pip install watchdog Pillow exifread requests pytesseract opencv-python pyyaml
   ```
   *(If you prefer a requirements file, create `requirements.txt` with these names.)*

3. **Verify Tesseract** is accessible (or set its path in configuration).

## Configuration

The script accepts configuration from three sources (in order of increasing precedence):
1. **YAML configuration file** (default or specified via `--config`).
2. **Environment variables** (override file values).
3. **Command‑line arguments** (currently only `--config`, but can be extended).

### YAML Configuration File

Create a file (e.g., `config.yaml`) with the following structure. All paths can be absolute or relative.

```yaml
# Required: input and output folders
input_folder: "./watch_folder"
output_folder: "./output"

# Optional settings with defaults shown
log_folder: "./logs"
watcher_recursive: true
image_extensions: [".jpg", ".jpeg", ".png", ".tiff", ".bmp"]
max_workers: 4
tesseract_cmd: "tesseract"                     # full path if not in PATH
geocoding_user_agent: "OSINT-Image-Collector/2.0 (contact@example.com)"
geocoding_cache_db: "./geocode_cache.db"
csv_summary_path: "./image_intel.csv"
enable_tamper_detection: true
enable_face_detection: false                    # requires opencv-python
update_metadata_on_tamper: false                # refresh metadata when tampered?
retry_attempts: 3
retry_delay: 2
request_timeout: 30                             # seconds for HTTP requests
max_file_size_mb: 100                            # skip larger files
health_check_interval: 30                         # seconds between health logs
log_level: "INFO"                                 # DEBUG, INFO, WARNING, ERROR
log_rotation_days: 7                              # keep logs for this many days
metrics_enabled: true                             # log metrics periodically
```

### Environment Variables

Set any of the following to override corresponding YAML keys:

| Environment Variable | Config Key |
|----------------------|------------|
| `INPUT_FOLDER`       | input_folder |
| `OUTPUT_FOLDER`      | output_folder |
| `LOG_FOLDER`         | log_folder |
| `MAX_WORKERS`        | max_workers |
| `TESSERACT_CMD`      | tesseract_cmd |
| `ENABLE_TAMPER_DETECTION` | enable_tamper_detection |
| `ENABLE_FACE_DETECTION`   | enable_face_detection |
| `RETRY_ATTEMPTS`      | retry_attempts |

Boolean values can be `true`, `1`, `yes`, `on` (case‑insensitive).

### Command‑Line Arguments

```
python osint_image_collector.py --config /path/to/config.yaml
```

If `--config` is omitted, the script looks for a file named `config.yaml` in the current directory? Actually the current code requires `--config`. But you can modify it to have a default if you wish.

## Usage

1. **Prepare your folders**: Create the input folder (where images will be dropped) and output folder (where results will be written). The script will create them if they don't exist.

2. **Run the script**:
   ```bash
   python osint_image_collector.py --config config.yaml
   ```

3. **Place images** into the input folder. The script will detect them and start processing.

4. **Monitor logs**: Check the console or the log file in `log_folder` for progress and errors.

5. **Stop gracefully**: Press `Ctrl+C` or send `SIGTERM` to the process.

## Outputs

### JSON Files
Each processed image produces a JSON file in the output folder, named as `{original_name}_{timestamp}.json`. It contains all extracted data:
- `filename`, `path`, `processing_time`
- `metadata`: raw EXIF tags
- `gps`: formatted GPS coordinates
- `address`: reverse geocoded address
- `ocr_text`: extracted text
- `faces`: list of detected faces with coordinates
- `hash`: SHA‑256 of the file
- `tamper_flag`: 1 if tamper detected, else 0
- `json_path`: path to this JSON file

### CSV Summary
A single CSV file (default `image_intel.csv`) with one row per processed image. Columns:
- `filename`
- `processing_time`
- `gps_coordinates`
- `address`
- `ocr_snippet` (first 200 chars)
- `hash`
- `tamper_flag` (0/1)
- `json_path`

### SQLite Database
The database file (default `geocode_cache.db`) contains three tables:
- `images`: tracks each file’s hash, first seen, last modified, tamper count.
- `image_metadata`: structured metadata (GPS, datetime, camera, software, dimensions, orientation) linked to image ID.
- `geocoding_cache`: cached reverse‑geocoding results.

You can query this database directly for analysis (e.g., `SELECT * FROM image_metadata WHERE camera_make_model LIKE '%Canon%';`).

## Understanding Key Features

### Tamper Detection
When `enable_tamper_detection: true`, the script computes a SHA‑256 hash of each image and stores it. On subsequent modifications, if the hash differs, it:
- Sets `tamper_flag: 1` in the JSON and CSV.
- Increments `tamper_count` in the `images` table.
- Optionally updates metadata if `update_metadata_on_tamper: true`.

### Reverse Geocoding with Circuit Breaker
- Coordinates are cached to avoid repeated API calls.
- If the Nominatim API fails repeatedly, the **circuit breaker** opens (default after 3 failures) and prevents further attempts for 5 minutes. This avoids hammering a failing service.
- Exponential backoff (`retry_delay * 2^attempt`) is used before the circuit opens.

### Face Detection
If `enable_face_detection: true`, the script uses OpenCV’s Haar cascade to detect faces. Bounding boxes are saved in the JSON.

### Worker Pool and Queue
- File system events are placed in a bounded queue (`maxsize=1000`).
- A pool of worker threads pulls events from the queue and submits actual processing tasks to a `ThreadPoolExecutor`.
- This prevents the watchdog thread from being blocked by slow processing.

### Health Checks
Every `health_check_interval` seconds, the script logs a health report:
- Database connectivity
- Worker pool status (are all workers alive?)
- Metrics: processed count, error count, queue depth

If `metrics_enabled: true`, this is logged as structured JSON.

### Graceful Shutdown
On `SIGINT` (Ctrl+C) or `SIGTERM`, the script:
- Stops accepting new file events.
- Waits for current processing to finish (up to a timeout).
- Closes database connections and exits cleanly.

## Logging

Logs are written to both console and a rotating file in `log_folder`. The file name is `osint-image_YYYYMMDD.log`. Rotation keeps logs for `log_rotation_days` days.

Log entries are structured with extra fields as JSON, e.g.:
```
2025-03-23 10:15:30,123 - OSINT-Image - INFO - Image processing completed successfully | {"filename": "IMG_001.jpg"}
```

You can change the log level via `log_level` in config.

## Performance Tuning

- **`max_workers`**: Number of concurrent image processors. Increase if you have a fast CPU and many images. Be mindful of API rate limits (geocoding).
- **`max_file_size_mb`**: Skip very large images that could consume memory.
- **Queue size**: Hard‑coded to 1000; you can change it in the `WorkerPool.__init__` if needed.

## Example: Minimal Configuration

```yaml
input_folder: "./incoming"
output_folder: "./results"
tesseract_cmd: "/usr/bin/tesseract"
enable_face_detection: true
```

Then run:
```bash
python osint_image_collector.py --config minimal.yaml
```

## Troubleshooting

### Tesseract not found
- Ensure Tesseract is installed and either in your PATH or set `tesseract_cmd` to the full path.
- On Windows, the path might be like `C:\Program Files\Tesseract-OCR\tesseract.exe`.

### OpenCV not installed for face detection
If you enable face detection but don’t have `opencv-python` installed, the script will log a warning and continue without faces.

### Geocoding fails consistently
- Check your internet connection.
- Nominatim may block you if you don’t set a proper `User-Agent`. The config includes `geocoding_user_agent` – set it to a descriptive string with your contact info.
- The circuit breaker will open after 3 failures; wait 5 minutes for it to close and retry.

### Database locked errors
Under heavy load, SQLite may throw “database is locked”. The script uses a thread lock to serialize writes, but if you have many workers, you might still hit contention. Reduce `max_workers` or switch to a more concurrent database (e.g., PostgreSQL) if needed – but for typical OSINT workloads, SQLite is sufficient.

### Images not being processed
- Check that the file extensions match those in `image_extensions`.
- Ensure the input folder is being watched (check logs for “Monitoring” line).
- If the script stops unexpectedly, check the log file for errors.

## Extending the Script

The code is modular; you can add new features by:
- Creating new classes (e.g., `ReverseImageSearch`).
- Injecting them into `ImageProcessor` or `WorkerPool`.
- Adding configuration options in `AppConfig`.

For example, to add a secondary geocoding provider, modify `GeocodingService` to try a second API after Nominatim fails.

## License

This script is provided under the MIT License. Use at your own risk; the authors are not responsible for any misuse or damage.

---

*For questions or contributions, please contact the repository maintainer.*
```
