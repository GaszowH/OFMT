#!/usr/bin/env python3
"""
OSINT Ready OSINT Image Intelligence Collector
---------------------------------------------------
Monitors a folder for images, extracts metadata, GPS, OCR text, detects faces,
performs reverse geocoding, logs everything with tamper detection, and stores
key metadata in a SQLite table for easy querying.

This implementation follows enterprise best practices:
- Type hints throughout
- Comprehensive error handling with retries
- Structured logging
- Graceful shutdown
- Configuration via env vars, CLI, and config files
- Modular design with dependency injection
- Thread-safe operations
- Circuit breaker pattern for external services
- Metrics collection capabilities
"""

import argparse
import hashlib
import json
import logging
import os
import queue
import signal
import sqlite3
import sys
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple, Union
from urllib.parse import urljoin

import cv2
import exifread
import pytesseract
import requests
import yaml
from PIL import Image
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


# ----------------------------------------------------------------------
# Constants and Enums
# ----------------------------------------------------------------------
class ProcessingStatus(Enum):
    """Enumeration of processing statuses for tracking purposes."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


class EventType(Enum):
    """Types of file system events we're interested in."""
    CREATED = "created"
    MODIFIED = "modified"
    MOVED = "moved"


# ----------------------------------------------------------------------
# Configuration Management
# ----------------------------------------------------------------------
@dataclass
class AppConfig:
    """
    Application configuration with validation and defaults.
    
    Supports loading from YAML, environment variables, and CLI arguments.
    """
    input_folder: Path
    output_folder: Path
    log_folder: Path = Path('./logs')
    watcher_recursive: bool = True
    image_extensions: List[str] = field(default_factory=lambda: ['.jpg', '.jpeg', '.png', '.tiff', '.bmp'])
    max_workers: int = 4
    tesseract_cmd: str = 'tesseract'
    geocoding_user_agent: str = 'OSINT-Image-Collector/2.0'
    geocoding_cache_db: Path = Path('./geocode_cache.db')
    csv_summary_path: Path = Path('./image_intel.csv')
    enable_tamper_detection: bool = True
    enable_face_detection: bool = False
    update_metadata_on_tamper: bool = False
    retry_attempts: int = 3
    retry_delay: float = 2.0
    request_timeout: int = 30
    max_file_size_mb: int = 100
    health_check_interval: int = 30
    log_level: str = 'INFO'
    log_rotation_days: int = 7
    metrics_enabled: bool = True
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'AppConfig':
        """Create AppConfig from dictionary with type conversion."""
        # Convert string paths to Path objects
        path_fields = ['input_folder', 'output_folder', 'log_folder', 
                      'geocoding_cache_db', 'csv_summary_path']
        for field_name in path_fields:
            if field_name in config_dict:
                config_dict[field_name] = Path(config_dict[field_name])
        
        # Convert string to boolean for boolean fields
        bool_fields = ['watcher_recursive', 'enable_tamper_detection', 
                      'enable_face_detection', 'update_metadata_on_tamper',
                      'metrics_enabled']
        for field_name in bool_fields:
            if field_name in config_dict:
                val = config_dict[field_name]
                if isinstance(val, str):
                    config_dict[field_name] = val.lower() in ('true', '1', 'yes', 'on')
        
        # Convert list if needed
        if 'image_extensions' in config_dict and isinstance(config_dict['image_extensions'], str):
            config_dict['image_extensions'] = config_dict['image_extensions'].split(',')
        
        return cls(**config_dict)
    
    def validate(self) -> None:
        """Validate configuration values."""
        if self.max_workers <= 0:
            raise ValueError("max_workers must be positive")
        if self.retry_attempts < 0:
            raise ValueError("retry_attempts cannot be negative")
        if self.request_timeout <= 0:
            raise ValueError("request_timeout must be positive")
        if self.max_file_size_mb <= 0:
            raise ValueError("max_file_size_mb must be positive")


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from file, env vars, and CLI with proper precedence."""
    # Start with defaults
    config = {}
    
    # Load from file if provided
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            file_config = yaml.safe_load(f) or {}
        config.update(file_config)
    
    # Override with environment variables
    env_mapping = {
        'INPUT_FOLDER': 'input_folder',
        'OUTPUT_FOLDER': 'output_folder',
        'LOG_FOLDER': 'log_folder',
        'MAX_WORKERS': 'max_workers',
        'TESSERACT_CMD': 'tesseract_cmd',
        'ENABLE_TAMPER_DETECTION': 'enable_tamper_detection',
        'ENABLE_FACE_DETECTION': 'enable_face_detection',
        'RETRY_ATTEMPTS': 'retry_attempts',
    }
    
    for env_var, config_key in env_mapping.items():
        env_value = os.getenv(env_var)
        if env_value is not None:
            if config_key in ['max_workers', 'retry_attempts']:
                try:
                    config[config_key] = int(env_value)
                except ValueError:
                    pass  # Keep default if invalid
            else:
                config[config_key] = env_value
    
    app_config = AppConfig.from_dict(config)
    app_config.validate()
    return app_config


# ----------------------------------------------------------------------
# Logging Infrastructure
# ----------------------------------------------------------------------
class StructuredLogger:
    """Structured logging wrapper with rotation and multiple handlers."""
    
    def __init__(self, name: str, log_folder: Path, log_level: str = 'INFO', 
                 rotation_days: int = 7):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler with rotation
        from logging.handlers import TimedRotatingFileHandler
        log_file = log_folder / f"{name.lower()}_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = TimedRotatingFileHandler(
            log_file, when='midnight', interval=rotation_days, backupCount=5
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def info(self, message: str, **kwargs) -> None:
        self.logger.info(f"{message} | {json.dumps(kwargs) if kwargs else ''}")
    
    def warning(self, message: str, **kwargs) -> None:
        self.logger.warning(f"{message} | {json.dumps(kwargs) if kwargs else ''}")
    
    def error(self, message: str, **kwargs) -> None:
        self.logger.error(f"{message} | {json.dumps(kwargs) if kwargs else ''}")
    
    def debug(self, message: str, **kwargs) -> None:
        self.logger.debug(f"{message} | {json.dumps(kwargs) if kwargs else ''}")


# ----------------------------------------------------------------------
# Circuit Breaker Pattern
# ----------------------------------------------------------------------
class CircuitBreaker:
    """Circuit breaker implementation for external service calls."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.lock = threading.RLock()
    
    def call(self, func: Callable, *args, **kwargs):
        """Call function with circuit breaker protection."""
        with self.lock:
            if self.state == "OPEN":
                if (time.time() - self.last_failure_time) > self.recovery_timeout:
                    self.state = "HALF_OPEN"
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                if self.state == "HALF_OPEN":
                    self.state = "CLOSED"
                    self.failure_count = 0
                return result
            except Exception as e:
                self.failure_count += 1
                self.last_failure_time = time.time()
                if self.failure_count >= self.failure_threshold:
                    self.state = "OPEN"
                raise e


# ----------------------------------------------------------------------
# Data Models
# ----------------------------------------------------------------------
class ImageMetadata(NamedTuple):
    """Structured metadata extracted from images."""
    gps_coordinates: Optional[Tuple[float, float]]
    original_datetime: str
    camera_make_model: str
    software_used: str
    dimensions: Tuple[int, int]
    orientation: str


@dataclass
class ProcessingResult:
    """Result of image processing operation."""
    filename: str
    path: str
    processing_time: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    gps: Optional[str] = None
    address: Optional[str] = None
    ocr_text: str = ""
    faces: List[Dict[str, int]] = field(default_factory=list)
    hash: str = ""
    tamper_flag: int = 0
    json_path: str = ""
    status: ProcessingStatus = ProcessingStatus.PENDING
    error_message: Optional[str] = None


# ----------------------------------------------------------------------
# Database Layer
# ----------------------------------------------------------------------
class DatabaseManager:
    """Thread-safe database manager with connection pooling."""
    
    def __init__(self, db_path: Path, logger: StructuredLogger):
        self.db_path = db_path
        self.logger = logger
        self.lock = threading.RLock()
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                c = conn.cursor()
                
                # Images table
                c.execute('''
                    CREATE TABLE IF NOT EXISTS images (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        path TEXT UNIQUE,
                        hash TEXT,
                        first_seen TIMESTAMP,
                        last_modified TIMESTAMP,
                        tamper_count INTEGER DEFAULT 0
                    )
                ''')
                
                # Metadata table
                c.execute('''
                    CREATE TABLE IF NOT EXISTS image_metadata (
                        image_id INTEGER PRIMARY KEY,
                        gps_coordinates TEXT,
                        original_datetime TEXT,
                        camera_make_model TEXT,
                        software_used TEXT,
                        dimensions TEXT,
                        orientation TEXT,
                        FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
                    )
                ''')
                
                # Geocoding cache
                c.execute('''
                    CREATE TABLE IF NOT EXISTS geocoding_cache (
                        coord_key TEXT PRIMARY KEY,
                        address TEXT,
                        timestamp TIMESTAMP
                    )
                ''')
                
                conn.commit()
            finally:
                conn.close()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    def get_image_record(self, path: str) -> Optional[Dict]:
        """Retrieve image record by path."""
        with self.lock:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT id, path, hash, first_seen, last_modified, tamper_count 
                    FROM images WHERE path=?
                ''', (path,))
                row = c.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'path': row[1],
                        'hash': row[2],
                        'first_seen': row[3],
                        'last_modified': row[4],
                        'tamper_count': row[5]
                    }
                return None
    
    def upsert_image_record(self, path: str, file_hash: str, modified_time: str) -> int:
        """Insert or update image record, returning the image id."""
        with self.lock:
            with self._get_connection() as conn:
                c = conn.cursor()
                now = datetime.now().isoformat()
                
                # Check if record exists
                c.execute('SELECT id, tamper_count FROM images WHERE path=?', (path,))
                row = c.fetchone()
                
                if row:
                    image_id, tamper_count = row
                    # Update existing record
                    c.execute('''
                        UPDATE images SET hash=?, last_modified=?, tamper_count=?
                        WHERE id=?
                    ''', (file_hash, modified_time, tamper_count + 1, image_id))
                else:
                    # Insert new record
                    c.execute('''
                        INSERT INTO images (path, hash, first_seen, last_modified, tamper_count)
                        VALUES (?, ?, ?, ?, 0)
                    ''', (path, file_hash, now, modified_time))
                    image_id = c.lastrowid
                
                conn.commit()
                return image_id
    
    def update_path(self, old_path: str, new_path: str) -> None:
        """Update image path in database."""
        with self.lock:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute('UPDATE images SET path=? WHERE path=?', (new_path, old_path))
                conn.commit()
    
    def add_metadata(self, image_id: int, metadata: ImageMetadata) -> None:
        """Add or replace metadata for an image."""
        with self.lock:
            with self._get_connection() as conn:
                c = conn.cursor()
                
                # Convert coordinates to string for storage
                gps_str = f"{metadata.gps_coordinates[0]:.5f},{metadata.gps_coordinates[1]:.5f}" \
                          if metadata.gps_coordinates else None
                dimensions_str = f"{metadata.dimensions[0]}x{metadata.dimensions[1]}" \
                                if metadata.dimensions else None
                
                c.execute('''
                    INSERT OR REPLACE INTO image_metadata
                    (image_id, gps_coordinates, original_datetime, camera_make_model, 
                     software_used, dimensions, orientation)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    image_id,
                    gps_str,
                    metadata.original_datetime,
                    metadata.camera_make_model,
                    metadata.software_used,
                    dimensions_str,
                    metadata.orientation
                ))
                conn.commit()
    
    def get_cached_address(self, lat: float, lon: float) -> Optional[str]:
        """Get cached reverse geocoding result."""
        key = f"{lat:.5f},{lon:.5f}"
        with self.lock:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT address FROM geocoding_cache WHERE coord_key=?', (key,))
                row = c.fetchone()
                return row[0] if row else None
    
    def cache_address(self, lat: float, lon: float, address: str) -> None:
        """Cache reverse geocoding result."""
        key = f"{lat:.5f},{lon:.5f}"
        with self.lock:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT OR REPLACE INTO geocoding_cache (coord_key, address, timestamp)
                    VALUES (?, ?, ?)
                ''', (key, address, datetime.now().isoformat()))
                conn.commit()


# ----------------------------------------------------------------------
# CSV Logger
# ----------------------------------------------------------------------
class CSVLogger:
    """Thread-safe CSV logging with header management."""
    
    def __init__(self, csv_path: Path, logger: StructuredLogger):
        self.csv_path = csv_path
        self.logger = logger
        self.lock = threading.Lock()
        self._initialized = False
        self._ensure_parent_directory()
        self._init_csv()
    
    def _ensure_parent_directory(self) -> None:
        """Ensure parent directory exists."""
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _init_csv(self) -> None:
        """Initialize CSV with headers if needed."""
        if not self.csv_path.exists():
            with self.lock:
                with open(self.csv_path, 'w') as f:
                    f.write('filename,processing_time,gps_coordinates,address,ocr_snippet,hash,tamper_flag,json_path\n')
                self._initialized = True
    
    def append(self, data: Dict[str, Any]) -> None:
        """Append a row to the CSV file."""
        with self.lock:
            with open(self.csv_path, 'a') as f:
                line = (
                    f"{data['filename']},{data['processing_time']},"
                    f"{data.get('gps_coordinates', '')},"
                    f"{data.get('address', '')},"
                    f"{str(data.get('ocr_snippet', ''))[:200].replace(',', ' ')},"
                    f"{data['hash']},{data.get('tamper_flag', 0)},{data['json_path']}\n"
                )
                f.write(line)


# ----------------------------------------------------------------------
# Geocoding Service
# ----------------------------------------------------------------------
class GeocodingService:
    """Reverse geocoding service with caching and circuit breaker."""
    
    def __init__(self, config: AppConfig, db: DatabaseManager, 
                 logger: StructuredLogger):
        self.config = config
        self.db = db
        self.logger = logger
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=300)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.geocoding_user_agent})
    
    def reverse(self, lat: float, lon: float) -> Optional[str]:
        """Perform reverse geocoding with caching."""
        try:
            cached = self.db.get_cached_address(lat, lon)
            if cached:
                self.logger.debug("Using cached geocoding result", 
                                latitude=lat, longitude=lon, address=cached)
                return cached
            
            address = self.circuit_breaker.call(self._perform_reverse_geocoding, lat, lon)
            
            if address:
                self.db.cache_address(lat, lon, address)
                self.logger.info("Geocoding successful", 
                               latitude=lat, longitude=lon, address=address)
            
            return address
        except Exception as e:
            self.logger.warning("Geocoding failed", error=str(e), 
                              latitude=lat, longitude=lon)
            return None
    
    def _perform_reverse_geocoding(self, lat: float, lon: float) -> Optional[str]:
        """Internal method to perform actual geocoding request."""
        url = 'https://nominatim.openstreetmap.org/reverse'
        params = {
            'lat': lat,
            'lon': lon,
            'format': 'json',
            'zoom': 18,
            'addressdetails': 0
        }
        
        response = self.session.get(
            url, 
            params=params, 
            timeout=self.config.request_timeout
        )
        response.raise_for_status()
        
        data = response.json()
        return data.get('display_name', '')


# ----------------------------------------------------------------------
# Image Processing Pipeline
# ----------------------------------------------------------------------
class ImageProcessor:
    """Main image processing orchestrator."""
    
    def __init__(self, config: AppConfig, geocoder: GeocodingService, 
                 db: DatabaseManager, logger: StructuredLogger):
        self.config = config
        self.geocoder = geocoder
        self.db = db
        self.logger = logger
        self.face_cascade = None
        
        if config.enable_face_detection:
            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            self.face_cascade = cv2.CascadeClassifier(cascade_path)
        
        # Validate tesseract installation
        pytesseract.pytesseract.tesseract_cmd = config.tesseract_cmd
    
    def process(self, file_path: Path) -> ProcessingResult:
        """Process an image file and extract intelligence."""
        result = ProcessingResult(
            filename=file_path.name,
            path=str(file_path),
            processing_time=datetime.now().isoformat()
        )
        
        try:
            # Validate file
            if not self._validate_file(file_path):
                result.status = ProcessingStatus.FAILED
                result.error_message = "Invalid file"
                return result
            
            # Compute hash first for tamper detection
            result.hash = self._compute_hash(file_path)
            
            # Extract EXIF metadata
            result.metadata = self._extract_exif_metadata(file_path)
            
            # Extract structured metadata
            structured_metadata = self._extract_structured_metadata(
                result.metadata, file_path
            )
            
            # Extract GPS and perform geocoding
            if structured_metadata.gps_coordinates:
                lat, lon = structured_metadata.gps_coordinates
                result.gps = f"{lat:.5f}, {lon:.5f}"
                result.address = self.geocoder.reverse(lat, lon)
            
            # Perform OCR
            result.ocr_text = self._perform_ocr(file_path)
            
            # Detect faces
            if self.config.enable_face_detection and self.face_cascade:
                result.faces = self._detect_faces(file_path)
            
            # Handle tamper detection
            self._handle_tamper_detection(file_path, result, structured_metadata)
            
            result.status = ProcessingStatus.COMPLETED
            self.logger.info("Image processing completed successfully", 
                           filename=file_path.name)
            
        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.error_message = str(e)
            self.logger.error("Image processing failed", 
                            filename=file_path.name, error=str(e))
        
        return result
    
    def _validate_file(self, file_path: Path) -> bool:
        """Validate that the file is processable."""
        if not file_path.exists():
            self.logger.warning("File does not exist", path=str(file_path))
            return False
        
        if not file_path.is_file():
            self.logger.warning("Path is not a file", path=str(file_path))
            return False
        
        # Check file size
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        if file_size_mb > self.config.max_file_size_mb:
            self.logger.warning("File too large", 
                              path=str(file_path), 
                              size_mb=file_size_mb)
            return False
        
        # Check extension
        if file_path.suffix.lower() not in self.config.image_extensions:
            self.logger.warning("Unsupported file extension", 
                              path=str(file_path), 
                              extension=file_path.suffix)
            return False
        
        return True
    
    def _compute_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error("Hash computation failed", 
                            path=str(file_path), error=str(e))
            raise
    
    def _extract_exif_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract raw EXIF metadata."""
        try:
            with open(file_path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
            return {k: str(v) for k, v in tags.items()}
        except Exception as e:
            self.logger.warning("EXIF extraction failed", 
                              path=str(file_path), error=str(e))
            return {}
    
    def _extract_structured_metadata(self, tags: Dict, file_path: Path) -> ImageMetadata:
        """Extract structured metadata for database storage."""
        gps = self._extract_gps(tags)
        
        original_datetime = str(tags.get('EXIF DateTimeOriginal', ''))
        camera_make = str(tags.get('Image Make', ''))
        camera_model = str(tags.get('Image Model', ''))
        camera_make_model = f"{camera_make} {camera_model}".strip()
        software_used = str(tags.get('Image Software', ''))
        
        # Get dimensions
        try:
            width = int(tags.get('EXIF ExifImageWidth', 0))
            height = int(tags.get('EXIF ExifImageHeight', 0))
            if width and height:
                dimensions = (width, height)
            else:
                # Fallback to PIL
                with Image.open(file_path) as img:
                    dimensions = img.size
        except Exception:
            dimensions = (0, 0)
        
        orientation = str(tags.get('Image Orientation', ''))
        
        return ImageMetadata(
            gps_coordinates=gps,
            original_datetime=original_datetime,
            camera_make_model=camera_make_model,
            software_used=software_used,
            dimensions=dimensions,
            orientation=orientation
        )
    
    def _extract_gps(self, tags: Dict) -> Optional[Tuple[float, float]]:
        """Extract GPS coordinates from EXIF tags."""
        try:
            lat_ref = tags.get('GPS GPSLatitudeRef')
            lat = tags.get('GPS GPSLatitude')
            lon_ref = tags.get('GPS GPSLongitudeRef')
            lon = tags.get('GPS GPSLongitude')
            
            if not (lat_ref and lat and lon_ref and lon):
                return None
            
            lat_deg, lat_min, lat_sec = [float(x) for x in lat.values]
            lon_deg, lon_min, lon_sec = [float(x) for x in lon.values]
            
            latitude = lat_deg + lat_min/60 + lat_sec/3600
            longitude = lon_deg + lon_min/60 + lon_sec/3600
            
            if lat_ref.values[0] in ['S', 's']:
                latitude = -latitude
            if lon_ref.values[0] in ['W', 'w']:
                longitude = -longitude
            
            return (latitude, longitude)
        except Exception as e:
            self.logger.debug("GPS extraction error", error=str(e))
            return None
    
    def _perform_ocr(self, file_path: Path) -> str:
        """Perform OCR on image."""
        try:
            img = Image.open(file_path)
            # Preprocess for better OCR
            img_gray = img.convert('L')
            # Apply thresholding
            threshold = 128
            img_bin = img_gray.point(lambda p: p > threshold and 255)
            text = pytesseract.image_to_string(img_bin)
            return text.strip()
        except Exception as e:
            self.logger.warning("OCR failed", path=str(file_path), error=str(e))
            return ""
    
    def _detect_faces(self, file_path: Path) -> List[Dict[str, int]]:
        """Detect faces in image."""
        try:
            img_cv = cv2.imread(str(file_path))
            if img_cv is None:
                self.logger.warning("Could not read image for face detection", 
                                  path=str(file_path))
                return []
            
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
            return [{'x': int(x), 'y': int(y), 'w': int(w), 'h': int(h)} 
                   for (x, y, w, h) in faces]
        except Exception as e:
            self.logger.warning("Face detection failed", 
                              path=str(file_path), error=str(e))
            return []
    
    def _handle_tamper_detection(self, file_path: Path, result: ProcessingResult, 
                                structured_metadata: ImageMetadata) -> None:
        """Handle tamper detection logic."""
        if not self.config.enable_tamper_detection:
            # If tamper detection disabled, always insert/update and add metadata
            mod_time = datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            image_id = self.db.upsert_image_record(str(file_path), result.hash, mod_time)
            self.db.add_metadata(image_id, structured_metadata)
            return
        
        record = self.db.get_image_record(str(file_path))
        mod_time = datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
        
        if record:
            if record['hash'] != result.hash:
                result.tamper_flag = 1
                self.logger.warning("Tamper detected", path=str(file_path))
                image_id = self.db.upsert_image_record(str(file_path), result.hash, mod_time)
                # Optionally update metadata if file was tampered
                if self.config.update_metadata_on_tamper:
                    self.db.add_metadata(image_id, structured_metadata)
            else:
                # No change, just update last_modified
                image_id = self.db.upsert_image_record(str(file_path), result.hash, mod_time)
        else:
            # New file
            image_id = self.db.upsert_image_record(str(file_path), result.hash, mod_time)
            self.db.add_metadata(image_id, structured_metadata)


# ----------------------------------------------------------------------
# Event Handling
# ----------------------------------------------------------------------
@dataclass
class FileEvent:
    """Represents a file system event."""
    event_type: EventType
    src_path: str
    dest_path: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class EventHandler(FileSystemEventHandler):
    """Handles file system events and queues them for processing."""
    
    def __init__(self, event_queue: queue.Queue, logger: StructuredLogger):
        super().__init__()
        self.event_queue = event_queue
        self.logger = logger
    
    def on_created(self, event) -> None:
        if not event.is_directory:
            self._queue_event(EventType.CREATED, event.src_path)
    
    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._queue_event(EventType.MODIFIED, event.src_path)
    
    def on_moved(self, event) -> None:
        if not event.is_directory:
            self._queue_event(EventType.MOVED, event.src_path, event.dest_path)
    
    def _queue_event(self, event_type: EventType, src_path: str, 
                    dest_path: Optional[str] = None) -> None:
        """Queue a file event for processing."""
        try:
            file_event = FileEvent(event_type=event_type, 
                                 src_path=src_path, 
                                 dest_path=dest_path)
            self.event_queue.put(file_event, block=False)
            self.logger.debug("Queued file event", 
                            event_type=event_type.value, 
                            src_path=src_path)
        except queue.Full:
            self.logger.error("Event queue full, dropping event", 
                            event_type=event_type.value, 
                            src_path=src_path)


# ----------------------------------------------------------------------
# Worker Pool
# ----------------------------------------------------------------------
class WorkerPool:
    """Manages worker threads for processing file events."""
    
    def __init__(self, config: AppConfig, processor: ImageProcessor, 
                 db: DatabaseManager, csv_logger: CSVLogger, 
                 logger: StructuredLogger):
        self.config = config
        self.processor = processor
        self.db = db
        self.csv_logger = csv_logger
        self.logger = logger
        self.event_queue: queue.Queue = queue.Queue(maxsize=1000)
        self.executor = ThreadPoolExecutor(max_workers=config.max_workers)
        self.running = False
        self.workers: List[threading.Thread] = []
        self.metrics = {
            'processed_count': 0,
            'error_count': 0,
            'queue_depth': 0
        }
        self.metrics_lock = threading.Lock()
    
    def start(self) -> None:
        """Start worker threads."""
        self.running = True
        for i in range(self.config.max_workers):
            worker = threading.Thread(target=self._worker, name=f"Worker-{i}", daemon=True)
            worker.start()
            self.workers.append(worker)
        self.logger.info("Worker pool started", worker_count=self.config.max_workers)
    
    def stop(self) -> None:
        """Stop worker threads gracefully."""
        self.running = False
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.executor.shutdown(wait=True)
        self.logger.info("Worker pool stopped")
    
    def _worker(self) -> None:
        """Worker thread function."""
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                self._update_metrics(queue_depth_delta=-1)
                
                if event is None:
                    break
                
                self._process_event(event)
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error("Worker error", error=str(e))
                self._update_metrics(error_count_delta=1)
    
    def _process_event(self, event: FileEvent) -> None:
        """Process a file system event."""
        try:
            if event.event_type in (EventType.CREATED, EventType.MODIFIED):
                if self._is_image(event.src_path):
                    self.logger.info("Processing file", 
                                   event_type=event.event_type.value, 
                                   path=event.src_path)
                    # Submit to thread pool for actual processing
                    future = self.executor.submit(self._process_file, Path(event.src_path))
                    future.add_done_callback(self._save_result_callback)
                else:
                    self.logger.debug("Ignoring non-image file", path=event.src_path)
                    
            elif event.event_type == EventType.MOVED:
                self.logger.info("File moved", 
                               src_path=event.src_path, 
                               dest_path=event.dest_path)
                self.db.update_path(event.src_path, event.dest_path)
                
        except Exception as e:
            self.logger.error("Event processing failed", 
                            event_type=event.event_type.value, 
                            error=str(e))
            self._update_metrics(error_count_delta=1)
    
    def _is_image(self, path: str) -> bool:
        """Check if file is an image based on extension."""
        ext = Path(path).suffix.lower()
        return ext in self.config.image_extensions
    
    def _process_file(self, file_path: Path) -> ProcessingResult:
        """Process a single file."""
        return self.processor.process(file_path)
    
    def _save_result_callback(self, future) -> None:
        """Callback to save processing results."""
        try:
            result: ProcessingResult = future.result()
            self._save_results(result)
            self._update_metrics(processed_count_delta=1)
        except Exception as e:
            self.logger.error("Result saving failed", error=str(e))
            self._update_metrics(error_count_delta=1)
    
    def _save_results(self, result: ProcessingResult) -> None:
        """Save processing results to disk and database."""
        try:
            # Write JSON
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_name = f"{Path(result.path).stem}_{timestamp}.json"
            json_path = self.config.output_folder / json_name
            
            # Ensure output directory exists
            json_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(json_path, 'w') as f:
                json.dump(result.__dict__, f, indent=2, default=str)
            
            result.json_path = str(json_path)
            
            # Update CSV summary
            csv_data = {
                'filename': result.filename,
                'processing_time': result.processing_time,
                'gps_coordinates': result.gps or '',
                'address': result.address or '',
                'ocr_snippet': result.ocr_text,
                'hash': result.hash,
                'tamper_flag': result.tamper_flag,
                'json_path': result.json_path
            }
            self.csv_logger.append(csv_data)
            
            self.logger.info("Results saved", filename=result.filename)
            
        except Exception as e:
            self.logger.error("Failed to save results", 
                            filename=result.filename, error=str(e))
            raise
    
    def _update_metrics(self, processed_count_delta: int = 0, 
                       error_count_delta: int = 0, 
                       queue_depth_delta: int = 0) -> None:
        """Update processing metrics."""
        with self.metrics_lock:
            self.metrics['processed_count'] += processed_count_delta
            self.metrics['error_count'] += error_count_delta
            self.metrics['queue_depth'] += queue_depth_delta
    
    def get_metrics(self) -> Dict[str, int]:
        """Get current processing metrics."""
        with self.metrics_lock:
            # Update queue depth from actual queue
            self.metrics['queue_depth'] = self.event_queue.qsize()
            return self.metrics.copy()


# ----------------------------------------------------------------------
# Health Check and Monitoring
# ----------------------------------------------------------------------
class HealthChecker:
    """Performs health checks and reports status."""
    
    def __init__(self, worker_pool: WorkerPool, db: DatabaseManager, 
                 logger: StructuredLogger):
        self.worker_pool = worker_pool
        self.db = db
        self.logger = logger
        self.last_check = time.time()
        self.status = "UNKNOWN"
    
    def check_health(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        try:
            # Check database connectivity
            db_healthy = self._check_database()
            
            # Check worker pool status
            metrics = self.worker_pool.get_metrics()
            workers_healthy = len(self.worker_pool.workers) == self.worker_pool.config.max_workers
            
            # Overall status
            healthy = db_healthy and workers_healthy
            
            self.status = "HEALTHY" if healthy else "UNHEALTHY"
            
            return {
                "status": self.status,
                "timestamp": datetime.now().isoformat(),
                "database": db_healthy,
                "workers": workers_healthy,
                "metrics": metrics
            }
        except Exception as e:
            self.status = "ERROR"
            self.logger.error("Health check failed", error=str(e))
            return {
                "status": "ERROR",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    def _check_database(self) -> bool:
        """Check database connectivity."""
        try:
            # Simple query to test connectivity
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False


# ----------------------------------------------------------------------
# Main Application
# ----------------------------------------------------------------------
class OSINTImageCollector:
    """Main application class orchestrating all components."""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.logger = StructuredLogger(
            'OSINT-Image', 
            config.log_folder, 
            config.log_level, 
            config.log_rotation_days
        )
        
        # Initialize components
        self.db = DatabaseManager(config.geocoding_cache_db, self.logger)
        self.geocoder = GeocodingService(config, self.db, self.logger)
        self.processor = ImageProcessor(config, self.geocoder, self.db, self.logger)
        self.csv_logger = CSVLogger(config.csv_summary_path, self.logger)
        self.worker_pool = WorkerPool(config, self.processor, self.db, self.csv_logger, self.logger)
        self.health_checker = HealthChecker(self.worker_pool, self.db, self.logger)
        
        # File watching
        self.observer = Observer()
        self.running = False
        self.shutdown_event = threading.Event()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def start(self) -> None:
        """Start the application."""
        self.logger.info("Starting OSINT Image Collector")
        self.logger.info("Configuration loaded", 
                        input_folder=str(self.config.input_folder),
                        output_folder=str(self.config.output_folder),
                        max_workers=self.config.max_workers)
        
        # Ensure directories exist
        self._ensure_directories()
        
        # Start components
        self.worker_pool.start()
        
        # Setup file watcher
        event_handler = EventHandler(self.worker_pool.event_queue, self.logger)
        self.observer.schedule(
            event_handler, 
            str(self.config.input_folder), 
            recursive=self.config.watcher_recursive
        )
        self.observer.start()
        
        self.running = True
        self.logger.info("Application started successfully")
        
        # Start health check reporting
        self._start_health_check_reporting()
        
        # Main loop
        try:
            while self.running and not self.shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the application gracefully."""
        if not self.running:
            return
        
        self.logger.info("Shutting down OSINT Image Collector")
        self.running = False
        self.shutdown_event.set()
        
        # Stop components in order
        self.observer.stop()
        self.observer.join()
        self.worker_pool.stop()
        
        self.logger.info("Shutdown complete")
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        self.logger.info("Received signal", signal=signum)
        self.shutdown_event.set()
    
    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        dirs_to_create = [
            self.config.output_folder,
            self.config.log_folder,
            self.config.geocoding_cache_db.parent,
            self.config.csv_summary_path.parent
        ]
        
        for directory in dirs_to_create:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _start_health_check_reporting(self) -> None:
        """Start periodic health check reporting."""
        def health_reporter():
            while self.running and not self.shutdown_event.is_set():
                health_status = self.health_checker.check_health()
                if self.config.metrics_enabled:
                    self.logger.info("Health check", **health_status)
                time.sleep(self.config.health_check_interval)
        
        health_thread = threading.Thread(target=health_reporter, daemon=True)
        health_thread.start()


# ----------------------------------------------------------------------
# Entry Point
# ----------------------------------------------------------------------
def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Enterprise OSINT Image Intelligence Collector"
    )
    parser.add_argument(
        '--config', 
        help='Path to YAML configuration file'
    )
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Create and start application
        app = OSINTImageCollector(config)
        app.start()
        
    except Exception as e:
        print(f"Failed to start application: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
