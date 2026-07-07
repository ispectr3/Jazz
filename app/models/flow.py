from datetime import datetime
from app.extensions import db


class Flow(db.Model):
    __tablename__ = "flows"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    target = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default="pending")
    error = db.Column(db.Text)
    result_data = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    project = db.relationship("Project", backref=db.backref("flows", lazy=True))
    tasks = db.relationship("FlowTask", backref="flow", lazy=True, cascade="all, delete-orphan")

    def start(self):
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self, error: str = None):
        self.status = "failed" if error else "completed"
        self.error = error
        self.completed_at = datetime.utcnow()

    def to_dict(self):
        result = {
            "id": self.id,
            "project_id": self.project_id,
            "target": self.target,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "tasks_count": len(self.tasks),
            "tasks_completed": sum(1 for t in self.tasks if t.status == "completed"),
        }
        if self.result_data:
            import json
            result.update(json.loads(self.result_data))
        return result


class FlowTask(db.Model):
    __tablename__ = "flow_tasks"

    id = db.Column(db.Integer, primary_key=True)
    flow_id = db.Column(db.Integer, db.ForeignKey("flows.id"), nullable=False)
    phase_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default="pending")
    error = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    result_summary = db.Column(db.Text)
    retry_count = db.Column(db.Integer, default=0)

    subtasks = db.relationship("FlowSubtask", backref="task", lazy=True, cascade="all, delete-orphan")

    def start(self):
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self, error: str = None):
        self.status = "failed" if error else "completed"
        self.error = error
        self.completed_at = datetime.utcnow()

    def to_dict(self):
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "phase_name": self.phase_name,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "retry_count": self.retry_count,
            "subtasks_count": len(self.subtasks),
        }


class FlowSubtask(db.Model):
    __tablename__ = "flow_subtasks"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("flow_tasks.id"), nullable=False)
    tool_name = db.Column(db.String(100), nullable=False)
    tool_input = db.Column(db.Text)
    tool_output = db.Column(db.Text)
    status = db.Column(db.String(20), default="pending")
    error = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    attempt = db.Column(db.Integer, default=1)
    duration_ms = db.Column(db.Integer)

    def start(self):
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self, output: str = None, error: str = None):
        self.status = "failed" if error else "completed"
        self.tool_output = (output or "")[:5000]
        self.error = error
        self.completed_at = datetime.utcnow()
        if self.started_at:
            self.duration_ms = int((self.completed_at - self.started_at).total_seconds() * 1000)

    def to_dict(self):
        return {
            "id": self.id,
            "task_id": self.task_id,
            "tool_name": self.tool_name,
            "status": self.status,
            "error": self.error,
            "attempt": self.attempt,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
