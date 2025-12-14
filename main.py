from datetime import datetime, timedelta
import os
import io

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from sqlalchemy import inspect, text

import pandas as pd

# -------------------------------------------------
# APP + CONFIG
# -------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "DEV_ONLY_change_me")

db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///ukamba.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# -------------------------------------------------
# MODELOS
# -------------------------------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="gestor")  # admin | gestor | leitura
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Investor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    profissao = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ✅ Soft delete
    is_active = db.Column(db.Boolean, default=True)
    deleted_at = db.Column(db.DateTime, nullable=True)

    investments = db.relationship(
        "Investment",
        backref="investor",
        lazy=True,
        cascade="all, delete-orphan"
    )

    @property
    def numero_investimentos(self):
        return len(self.investments)


class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    investor_id = db.Column(db.Integer, db.ForeignKey("investor.id"), nullable=False)

    plano = db.Column(db.String(50))
    valor_investido = db.Column(db.Float, nullable=False)
    taxa_juro = db.Column(db.Float, nullable=False)
    meses = db.Column(db.Integer, nullable=False)

    data_inicio = db.Column(db.Date, nullable=False)
    data_fim = db.Column(db.Date, nullable=False)

    valor_reembolsado = db.Column(db.Float, default=0.0)

    def valor_total_a_receber(self):
        return float(self.valor_investido) * (1 + float(self.taxa_juro))

    def valor_em_falta(self):
        return float(self.valor_total_a_receber()) - float(self.valor_reembolsado)

    def dias_restantes(self):
        hoje = datetime.utcnow().date()
        return (self.data_fim - hoje).days

    def esta_atrasado(self):
        return self.dias_restantes() < 0 and self.valor_em_falta() > 0

    def esta_pago(self):
        return float(self.valor_reembolsado) >= float(self.valor_total_a_receber())


class ActionLog(db.Model):
    __tablename__ = "action_log"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(80), nullable=True)

    action = db.Column(db.String(60), nullable=False)       # ex: DELETE_INVESTOR
    entity = db.Column(db.String(60), nullable=False)       # ex: Investor, Investment, User
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# -------------------------------------------------
# LOGIN MANAGER
# -------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------------------------------------
# PERMISSÕES
# -------------------------------------------------

def require_roles(*roles):
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if not getattr(current_user, "is_active", True):
                logout_user()
                flash("Conta desativada. Contacte o administrador.", "danger")
                return redirect(url_for("login"))

            if getattr(current_user, "role", None) not in roles:
                flash("Sem permissão para aceder a esta página.", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


def log_action(action: str, entity: str, entity_id: int | None = None, details: str | None = None):
    try:
        uid = getattr(current_user, "id", None) if current_user.is_authenticated else None
        uname = getattr(current_user, "username", None) if current_user.is_authenticated else None
    except Exception:
        uid, uname = None, None

    al = ActionLog(
        user_id=uid,
        username=uname,
        action=action,
        entity=entity,
        entity_id=entity_id,
        details=details
    )
    db.session.add(al)
    db.session.commit()


# -------------------------------------------------
# MIGRAÇÃO “LEVE” (sem Alembic) PARA RENDER/POSTGRES
# -------------------------------------------------

def ensure_columns(table_name: str, columns_sql: list[str]):
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    if table_name not in tables:
        return

    existing_cols = [c["name"] for c in inspector.get_columns(table_name)]

    for col_name, sql_pg, sql_sqlite in columns_sql:
        if col_name in existing_cols:
            continue
        try:
            if "postgresql" in str(db.engine.url):
                db.session.execute(text(sql_pg))
            else:
                db.session.execute(text(sql_sqlite))
        except Exception:
            pass

    db.session.commit()


def init_db_and_seed_admin():
    with app.app_context():
        db.create_all()

        # ✅ garantir colunas novas em tabelas antigas
        ensure_columns("user", [
            ("is_active",
             'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE',
             "ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1"),
            ("created_at",
             'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS created_at TIMESTAMP',
             "ALTER TABLE user ADD COLUMN created_at DATETIME"),
        ])

        ensure_columns("investor", [
            ("is_active",
             'ALTER TABLE investor ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE',
             "ALTER TABLE investor ADD COLUMN is_active BOOLEAN DEFAULT 1"),
            ("deleted_at",
             'ALTER TABLE investor ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP',
             "ALTER TABLE investor ADD COLUMN deleted_at DATETIME"),
        ])

        # admin inicial
        admin_username = os.environ.get("ADMIN_USERNAME", "admin")
        admin_password = os.environ.get("ADMIN_PASSWORD", None)

        existing_admin = User.query.filter_by(username=admin_username).first()
        if not existing_admin:
            if not admin_password:
                admin_password = "123456"

            u = User(username=admin_username, role="admin", is_active=True)
            u.set_password(admin_password)
            db.session.add(u)
            db.session.commit()
            print(f"[OK] Admin criado: {admin_username}")

init_db_and_seed_admin()


# -------------------------------------------------
# AUTH
# -------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash("Conta desativada. Contacte o administrador.", "danger")
                return redirect(url_for("login"))

            login_user(user)
            log_action("LOGIN", "User", user.id, f"username={user.username}")
            flash("Login efetuado com sucesso!", "success")
            return redirect(url_for("dashboard"))

        flash("Usuário ou senha inválidos.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    try:
        log_action("LOGOUT", "User", getattr(current_user, "id", None), None)
    except Exception:
        pass
    logout_user()
    flash("Sessão terminada.", "info")
    return redirect(url_for("login"))


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("home.html")


# -------------------------------------------------
# DASHBOARD
# -------------------------------------------------

@app.route("/dashboard")
@require_roles("admin", "gestor", "leitura")
def dashboard():
    # Por padrão, escondemos investidores desativados
    show_inactive = request.args.get("show_inactive", "0") == "1"

    if show_inactive:
        investidores = Investor.query.order_by(Investor.id.desc()).all()
    else:
        investidores = Investor.query.filter_by(is_active=True).order_by(Investor.id.desc()).all()

    investments = Investment.query.all()

    # ✅ ORDENAÇÃO OPERACIONAL (Atrasado -> A vencer -> Em dia; mais urgente primeiro)
    def prioridade(inv: Investment):
        dias = inv.dias_restantes()
        em_falta = inv.valor_em_falta()

        if inv.esta_atrasado():
            tier = 0
        elif 0 <= dias <= 30 and em_falta > 0:
            tier = 1
        else:
            tier = 2

        return (tier, dias)

    investments = sorted(investments, key=prioridade)

    total_investido = sum(inv.valor_investido for inv in investments)
    total_reembolsado = sum(inv.valor_reembolsado for inv in investments)
    total_a_recuperar = sum(inv.valor_em_falta() for inv in investments)

    return render_template(
        "index.html",
        investidores=investidores,
        investments=investments,
        total_investido=total_investido,
        total_reembolsado=total_reembolsado,
        total_a_recuperar=total_a_recuperar,
        show_inactive=show_inactive
    )


@app.route("/ukamba")
@require_roles("admin", "gestor", "leitura")
def ukamba():
    return redirect(url_for("dashboard"))


@app.route("/investidor/<int:investor_id>")
@require_roles("admin", "gestor", "leitura")
def investor_detail(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    # leitura não deve abrir investidor desativado (para não confundir)
    if investor.is_active is False and current_user.role != "admin":
        flash("Este investidor está desativado.", "warning")
        return redirect(url_for("dashboard"))

    investments = investor.investments
    total_investido = sum(inv.valor_investido for inv in investments)
    total_reembolsado = sum(inv.valor_reembolsado for inv in investments)
    total_em_falta = sum(inv.valor_em_falta() for inv in investments)

    return render_template(
        "investor_detail.html",
        investor=investor,
        investments=investments,
        total_investido=total_investido,
        total_reembolsado=total_reembolsado,
        total_em_falta=total_em_falta,
    )


@app.route("/investidor/<int:investor_id>/relatorio")
@require_roles("admin", "gestor", "leitura")
def investor_report(investor_id):
    investor = Investor.query.get_or_404(investor_id)
    investments = investor.investments
    hoje = datetime.utcnow().date()

    total_investido = sum(inv.valor_investido for inv in investments)
    total_reembolsado = sum(inv.valor_reembolsado for inv in investments)
    total_em_falta = sum(inv.valor_em_falta() for inv in investments)

    return render_template(
        "investor_report.html",
        investor=investor,
        investments=investments,
        hoje=hoje,
        total_investido=total_investido,
        total_reembolsado=total_reembolsado,
        total_em_falta=total_em_falta,
    )


# -------------------------------------------------
# CRIAR INVESTIDOR / INVESTIMENTO
# -------------------------------------------------

@app.route("/novo_investidor", methods=["GET", "POST"])
@require_roles("admin", "gestor")
def new_investor():
    if request.method == "POST":
        nome = request.form["nome"]
        profissao = request.form.get("profissao", "")

        investor = Investor(nome=nome, profissao=profissao, is_active=True)
        db.session.add(investor)
        db.session.commit()

        log_action("CREATE_INVESTOR", "Investor", investor.id, f"nome={nome}")
        flash("Investidor criado com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_investor.html")


@app.route("/novo_investimento/<int:investor_id>", methods=["GET", "POST"])
@require_roles("admin", "gestor")
def new_investment(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    if investor.is_active is False:
        flash("Não pode criar investimento para um investidor desativado.", "danger")
        return redirect(url_for("investor_detail", investor_id=investor.id))

    if request.method == "POST":
        plano = request.form["plano"]
        valor_investido = float(request.form["valor_investido"])
        meses = int(request.form["meses"])

        if valor_investido >= 1_000_000:
            taxa_mensal = 0.03
        elif 500_000 <= valor_investido <= 999_999:
            taxa_mensal = 0.025
        elif 100_000 <= valor_investido <= 499_999:
            taxa_mensal = 0.02
        else:
            flash("Valor mínimo para investimento é 100.000 Kz.", "danger")
            return redirect(url_for("new_investment", investor_id=investor.id))

        taxa_juro = (1 + taxa_mensal) ** meses - 1

        data_inicio = datetime.strptime(request.form["data_inicio"], "%Y-%m-%d").date()
        data_fim = data_inicio + timedelta(days=30 * meses)

        investment = Investment(
            investor_id=investor.id,
            plano=plano,
            valor_investido=valor_investido,
            taxa_juro=taxa_juro,
            meses=meses,
            data_inicio=data_inicio,
            data_fim=data_fim,
        )

        db.session.add(investment)
        db.session.commit()

        log_action("CREATE_INVESTMENT", "Investment", investment.id, f"investor_id={investor.id}, valor={valor_investido}")
        flash("Investimento registado com sucesso!", "success")
        return redirect(url_for("investor_detail", investor_id=investor.id))

    return render_template("new_investment.html", investor=investor)


# -------------------------------------------------
# APAGAR INVESTIMENTO (admin)
# -------------------------------------------------

@app.route("/investimento/<int:investment_id>/deletar", methods=["POST"])
@require_roles("admin")
def delete_investment(investment_id):
    investment = Investment.query.get_or_404(investment_id)
    investor_id = investment.investor_id

    db.session.delete(investment)
    db.session.commit()

    log_action("DELETE_INVESTMENT", "Investment", investment_id, f"investor_id={investor_id}")
    flash("Investimento apagado com sucesso!", "info")
    return redirect(url_for("investor_detail", investor_id=investor_id))


# -------------------------------------------------
# PAGAR TOTAL (admin/gestor)
# -------------------------------------------------

@app.route("/investimento/<int:investment_id>/pagar_total", methods=["POST"])
@require_roles("admin", "gestor")
def pay_in_full(investment_id):
    investment = Investment.query.get_or_404(investment_id)

    total_previsto = float(investment.valor_total_a_receber())
    if float(investment.valor_reembolsado) >= total_previsto:
        flash("Este investimento já está marcado como pago.", "info")
        return redirect(url_for("investor_detail", investor_id=investment.investor_id))

    investment.valor_reembolsado = total_previsto
    db.session.commit()

    log_action("PAY_FULL", "Investment", investment.id, f"set valor_reembolsado={total_previsto}")
    flash("✅ Investimento marcado como PAGO (total) com sucesso!", "success")
    return redirect(url_for("investor_detail", investor_id=investment.investor_id))


# -------------------------------------------------
# ✅ APAGAR INVESTIDOR (SOFT DELETE) (admin)
# -------------------------------------------------

@app.route("/investidor/<int:investor_id>/deletar", methods=["POST"])
@require_roles("admin")
def delete_investor(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    # ✅ PROTEÇÃO: se existir investimento em aberto, bloqueia
    open_investments = [inv for inv in investor.investments if inv.valor_em_falta() > 0]
    if open_investments:
        flash("❌ Não pode apagar: este investidor ainda tem investimentos EM ABERTO.", "danger")
        return redirect(url_for("investor_detail", investor_id=investor.id))

    # ✅ Soft delete (não apaga do banco)
    investor.is_active = False
    investor.deleted_at = datetime.utcnow()
    db.session.commit()

    log_action("DELETE_INVESTOR_SOFT", "Investor", investor.id, f"nome={investor.nome}")
    flash("✅ Investidor desativado com sucesso (soft delete).", "success")
    return redirect(url_for("dashboard"))


# -------------------------------------------------
# RELATÓRIOS
# -------------------------------------------------

@app.route("/relatorios")
@require_roles("admin", "gestor", "leitura")
def relatorios():
    investments = Investment.query.all()
    investidores = Investor.query.filter_by(is_active=True).all()
    hoje = datetime.utcnow().date()

    total_investido = sum(inv.valor_investido for inv in investments)
    total_reembolsado = sum(inv.valor_reembolsado for inv in investments)
    total_a_recuperar = sum(inv.valor_em_falta() for inv in investments)

    total_atrasado = sum(inv.valor_em_falta() for inv in investments if inv.esta_atrasado())

    investimentos_ativos = [inv for inv in investments if inv.valor_em_falta() > 0]
    num_investimentos_ativos = len(investimentos_ativos)

    num_investidores = len(investidores)
    media_por_investidor = (total_investido / num_investidores) if num_investidores > 0 else 0

    total_previsto = sum(inv.valor_total_a_receber() for inv in investments)
    perc_recuperado = ((total_reembolsado / total_previsto) * 100) if total_previsto > 0 else 0

    investimentos_atrasados = [inv for inv in investments if inv.esta_atrasado()]
    a_vencer_30_dias = [
        inv for inv in investments
        if 0 <= (inv.data_fim - hoje).days <= 30 and inv.valor_em_falta() > 0
    ]

    resumo_investidores = []
    for invs in investidores:
        invs_investments = [i for i in investments if i.investor_id == invs.id]
        if not invs_investments:
            continue

        valor_investido_inv = sum(i.valor_investido for i in invs_investments)
        valor_reembolsado_inv = sum(i.valor_reembolsado for i in invs_investments)
        valor_em_falta_inv = sum(i.valor_em_falta() for i in invs_investments)
        atrasado_inv = any(i.esta_atrasado() for i in invs_investments)

        resumo_investidores.append({
            "investor": invs,
            "qtd": len(invs_investments),
            "valor_investido": valor_investido_inv,
            "valor_reembolsado": valor_reembolsado_inv,
            "valor_em_falta": valor_em_falta_inv,
            "atrasado": atrasado_inv,
        })

    return render_template(
        "relatorios.html",
        total_investido=total_investido,
        total_reembolsado=total_reembolsado,
        total_a_recuperar=total_a_recuperar,
        total_atrasado=total_atrasado,
        num_investimentos_ativos=num_investimentos_ativos,
        num_investidores=num_investidores,
        media_por_investidor=media_por_investidor,
        perc_recuperado=perc_recuperado,
        investimentos_atrasados=investimentos_atrasados,
        a_vencer_30_dias=a_vencer_30_dias,
        resumo_investidores=resumo_investidores,
    )


# -------------------------------------------------
# EXPORTAR EXCEL (admin/gestor)
# -------------------------------------------------

@app.route("/exportar/excel")
@require_roles("admin", "gestor")
def exportar_excel():
    investments = Investment.query.all()

    dados = []
    for inv in investments:
        dados.append({
            "Investidor": inv.investor.nome,
            "Plano": inv.plano,
            "Valor investido": inv.valor_investido,
            "Taxa juro (total período)": inv.taxa_juro,
            "Meses": inv.meses,
            "Data início": inv.data_inicio,
            "Data fim": inv.data_fim,
            "Valor reembolsado": inv.valor_reembolsado,
            "Valor em falta": inv.valor_em_falta(),
            "Dias restantes": inv.dias_restantes(),
            "Atrasado": "Sim" if inv.esta_atrasado() else "Não",
            "Pago": "Sim" if inv.esta_pago() else "Não",
        })

    df = pd.DataFrame(dados)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Investimentos")

    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name="ukamba_investimentos.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


# -------------------------------------------------
# ADMIN: BACKUP COMPLETO (Excel com várias abas)
# -------------------------------------------------

@app.route("/admin/backup/excel")
@require_roles("admin")
def admin_backup_excel():
    users = User.query.all()
    investors = Investor.query.all()
    investments = Investment.query.all()
    logs = ActionLog.query.order_by(ActionLog.id.desc()).limit(5000).all()

    df_users = pd.DataFrame([{
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at
    } for u in users])

    df_investors = pd.DataFrame([{
        "id": i.id,
        "nome": i.nome,
        "profissao": i.profissao,
        "is_active": i.is_active,
        "deleted_at": i.deleted_at,
        "created_at": i.created_at
    } for i in investors])

    df_investments = pd.DataFrame([{
        "id": inv.id,
        "investor_id": inv.investor_id,
        "investor_nome": inv.investor.nome if inv.investor else None,
        "plano": inv.plano,
        "valor_investido": inv.valor_investido,
        "taxa_juro": inv.taxa_juro,
        "meses": inv.meses,
        "data_inicio": inv.data_inicio,
        "data_fim": inv.data_fim,
        "valor_reembolsado": inv.valor_reembolsado,
        "valor_total_previsto": inv.valor_total_a_receber(),
        "valor_em_falta": inv.valor_em_falta(),
        "pago": inv.esta_pago(),
        "atrasado": inv.esta_atrasado(),
    } for inv in investments])

    df_logs = pd.DataFrame([{
        "id": l.id,
        "user_id": l.user_id,
        "username": l.username,
        "action": l.action,
        "entity": l.entity,
        "entity_id": l.entity_id,
        "details": l.details,
        "created_at": l.created_at,
    } for l in logs])

    output = io.BytesIO()
    fname = f"ukamba_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df_users.to_excel(writer, index=False, sheet_name="Users")
        df_investors.to_excel(writer, index=False, sheet_name="Investors")
        df_investments.to_excel(writer, index=False, sheet_name="Investments")
        df_logs.to_excel(writer, index=False, sheet_name="Audit_Log")

    output.seek(0)

    log_action("BACKUP_EXCEL", "System", None, f"file={fname}")
    return send_file(
        output,
        as_attachment=True,
        download_name=fname,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


# -------------------------------------------------
# ADMIN USERS (igual ao que tens)
# -------------------------------------------------

@app.route("/admin/users", methods=["GET", "POST"])
@require_roles("admin")
def admin_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "leitura").strip()

        if role not in ("admin", "gestor", "leitura"):
            flash("Role inválida.", "danger")
            return redirect(url_for("admin_users"))

        if not username or not password:
            flash("Preencha username e password.", "danger")
            return redirect(url_for("admin_users"))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Já existe um utilizador com esse username.", "warning")
            return redirect(url_for("admin_users"))

        u = User(username=username, role=role, is_active=True)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        log_action("CREATE_USER", "User", u.id, f"username={username}, role={role}")
        flash("Utilizador criado com sucesso!", "success")
        return redirect(url_for("admin_users"))

    users = User.query.order_by(User.id.desc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@require_roles("admin")
def admin_toggle_user(user_id):
    u = User.query.get_or_404(user_id)

    if u.id == current_user.id:
        flash("Não pode desativar o utilizador atual.", "warning")
        return redirect(url_for("admin_users"))

    u.is_active = not u.is_active
    db.session.commit()

    log_action("TOGGLE_USER", "User", u.id, f"is_active={u.is_active}")
    flash("Estado do utilizador atualizado.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@require_roles("admin")
def admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)

    new_password = request.form.get("new_password", "").strip()
    if not new_password:
        flash("Nova password vazia.", "danger")
        return redirect(url_for("admin_users"))

    u.set_password(new_password)
    db.session.commit()

    log_action("RESET_PASSWORD", "User", u.id, "password reset")
    flash("Password atualizada com sucesso.", "success")
    return redirect(url_for("admin_users"))


# -------------------------------------------------
# RUN LOCAL
# -------------------------------------------------

if __name__ == "__main__":
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=debug)
