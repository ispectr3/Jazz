from app.extensions import celery_app, db
from app.models.hashcat import CrackJob
from app.models.wireless import WirelessCapture
import subprocess
import os
from datetime import datetime

RESULT_DIR = os.path.join(os.getcwd(), 'cracked')
os.makedirs(RESULT_DIR, exist_ok=True)

@celery_app.task(name='hashcat_tasks.run_hashcat_crack')
def run_hashcat_crack(job_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        job = CrackJob.query.get(job_id)
        if not job:
            return "Job not found"

        job.status = 'running'
        db.session.commit()

        hash_file = job.hash_file_path
        wordlist = job.wordlist_path

        if not os.path.exists(hash_file):
            job.status = 'failed'
            job.raw_output = f'Hash file not found: {hash_file}'
            db.session.commit()
            return "Hash file not found"

        if not os.path.exists(wordlist):
            job.status = 'failed'
            job.raw_output = f'Wordlist not found: {wordlist}'
            db.session.commit()
            return "Wordlist not found"

        base = os.path.splitext(os.path.basename(hash_file))[0]
        potfile_path = os.path.join(RESULT_DIR, f'{base}_cracked.txt')
        show_path = os.path.join(RESULT_DIR, f'{base}_show.txt')

        cmd = [
            'hashcat', '-m', str(job.hash_mode),
            '-a', '0',
            hash_file, wordlist,
            '--potfile-path', potfile_path,
            '-O', '--force',
            '--show'
        ]

        try:
            result = subprocess.run(
                ['hashcat', '-m', str(job.hash_mode), '-a', '0',
                 hash_file, wordlist,
                 '--potfile-path', potfile_path,
                 '-O', '--force'],
                capture_output=True, text=True, timeout=300
            )

            show_result = subprocess.run(
                ['hashcat', '-m', str(job.hash_mode), '--show', hash_file,
                 '--potfile-path', potfile_path],
                capture_output=True, text=True, timeout=30
            )

            job.raw_output = result.stdout + result.stderr
            job.result_path = potfile_path

            if show_result.stdout:
                lines = [l.strip() for l in show_result.stdout.splitlines() if l.strip()]
                job.cracked_count = len(lines)
                with open(show_path, 'w') as f:
                    f.write('\n'.join(lines))
            else:
                job.cracked_count = 0

            if os.path.exists(potfile_path):
                with open(potfile_path) as f:
                    job.cracked_count = sum(1 for _ in f if _.strip())

            job.status = 'done'
            job.completed_at = datetime.utcnow()

            if job.cracked_count == 0:
                job.status = 'no_crack'

            db.session.commit()
            return f"Crack done: {job.cracked_count} hashes cracked"

        except subprocess.TimeoutExpired:
            job.status = 'timeout'
            job.raw_output = 'Hashcat timed out after 300s'
            db.session.commit()
            return "Timeout"
        except FileNotFoundError:
            job.status = 'failed'
            job.raw_output = 'hashcat binary not found. Install with: brew install hashcat'
            db.session.commit()
            return "hashcat not found"
        except Exception as e:
            job.status = 'failed'
            job.raw_output = str(e)
            db.session.commit()
            return f"Error: {e}"
