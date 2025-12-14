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

# ✅ SECRET_KEY vem do Render (Environment)
# Se não existir, usa um fallback (apenas para teste local)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "DEV_ONLY_change_me")

# ✅ DATABASE_URL vem do Render (Environment)
# Render/Heroku às vezes usam postgres:// e o SQLAlchemy prefere postgresql://
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# fallback local
app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///ukamba.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"  # rota de login


# -------------------------------------------------
# MODELOS (TABELAS DO BANCO)
# -------------------------------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    # roles: admin | gestor | leitura
    role = db.Column(db.String(20), nullable=False, default="gestor")

    # permite bloquear conta
    is_active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return self.role == "admin"

    def is_gestor(self) -> bool:
        return self.role == "gestor"


class Investor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    profissao = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    investments = db.relationship("Investment", backref="investor", lazy=True)

    @property
    def numero_investimentos(self):
        return len(self.investments)


class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    investor_id = db.Column(db.Integer, db.ForeignKey("investor.id"), nullable=False)

    plano = db.Column(db.String(50))
    valor_investido = db.Column(db.Float, nullable=False)
    taxa_juro = db.Column(db.Float, nullable=False)  # taxa total do período (juros compostos)
    meses = db.Column(db.Integer, nullable=False)

    data_inicio = db.Column(db.Date, nullable=False)
    data_fim = db.Column(db.Date, nullable=False)

    valor_reembolsado = db.Column(db.Float, default=0.0)

    def valor_total_a_receber(self):
        return self.valor_investido * (1 + self.taxa_juro)

    def valor_em_falta(self):
        return self.valor_total_a_receber() - self.valor_reembolsado

    def dias_restantes(self):
        hoje = datetime.utcnow().date()
        return (self.data_fim - hoje).days

    def esta_atrasado(self):
        return self.dias_restantes() < 0 and self.valor_em_falta() > 0


# -------------------------------------------------
# LOGIN MANAGER
# -------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------------------------------------
# PERMISSÕES (REGRAS DE ACESSO)
# -------------------------------------------------

def require_roles(*roles):
    """
    roles possíveis: "admin", "gestor", "leitura"
    """
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            if not getattr(current_user, "is_active", True):
                logout_user()
                flash("Conta desativada. Contacte o administrador.", "danger")
                return redirect(url_for("login"))

            user_role = getattr(current_user, "role", None)
            if user_role not in roles:
                flash("Sem permissão para aceder a esta página.", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -------------------------------------------------
# CORREÇÃO PARA O RENDER (POSTGRES): garantir colunas na tabela user
# -------------------------------------------------

def ensure_user_table_columns():
    """
    Se o Postgres do Render já tinha uma tabela 'user' antiga,
    esta função adiciona colunas novas (is_active, created_at)
    para evitar Internal Server Error.
    """
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

    if "user" not in tables:
        return  # create_all vai criar

    cols = [c["name"] for c in inspector.get_columns("user")]

    # --- is_active ---
    if "is_active" not in cols:
        try:
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE'))
        except Exception:
            try:
                db.session.execute(text("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1"))
            except Exception:
                pass

    # --- created_at ---
    if "created_at" not in cols:
        try:
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS created_at TIMESTAMP'))
        except Exception:
            try:
                db.session.execute(text("ALTER TABLE user ADD COLUMN created_at DATETIME"))
            except Exception:
                pass

    db.session.commit()


# -------------------------------------------------
# INICIALIZAÇÃO DO BANCO + ADMIN INICIAL (PRODUÇÃO)
# -------------------------------------------------

def init_db_and_seed_admin():
    """
    - Cria tabelas
    - Garante colunas na tabela user (Render/Postgres)
    - Cria admin inicial se não existir
    """
    with app.app_context():
        db.create_all()

        # 🔧 garante colunas ANTES de consultar User.query (evita crash no Render)
        ensure_user_table_columns()

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
            print(f"[OK] Admin criado: {admin_username} / (senha definida no ENV ou fallback)")


init_db_and_seed_admin()


# -------------------------------------------------
# ROTAS DE AUTENTICAÇÃO
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
            flash("Login efetuado com sucesso!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Usuário ou senha inválidos.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sessão terminada.", "info")
    return redirect(url_for("login"))


# -------------------------------------------------
# HOME (RAIZ DO SITE)
# -------------------------------------------------

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("home.html")


# -------------------------------------------------
# DASHBOARD E INVESTIDORES (LEITURA/gestor/admin)
# -------------------------------------------------

@app.route("/dashboard")
@require_roles("admin", "gestor", "leitura")
def dashboard():
    investidores = Investor.query.all()
    investments = Investment.query.all()

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
    )


@app.route("/ukamba")
@require_roles("admin", "gestor", "leitura")
def ukamba():
    return redirect(url_for("dashboard"))


@app.route("/investidor/<int:investor_id>")
@require_roles("admin", "gestor", "leitura")
def investor_detail(investor_id):
    investor = Investor.query.get_or_404(investor_id)
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
# NOVO INVESTIDOR / NOVO INVESTIMENTO (gestor/admin)
# -------------------------------------------------

@app.route("/novo_investidor", methods=["GET", "POST"])
@require_roles("admin", "gestor")
def new_investor():
    if request.method == "POST":
        nome = request.form["nome"]
        profissao = request.form.get("profissao", "")

        investor = Investor(nome=nome, profissao=profissao)
        db.session.add(investor)
        db.session.commit()

        flash("Investidor criado com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_investor.html")


@app.route("/novo_investimento/<int:investor_id>", methods=["GET", "POST"])
@require_roles("admin", "gestor")
def new_investment(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    if request.method == "POST":
        plano = request.form["plano"]
        valor_investido = float(request.form["valor_investido"])
        meses = int(request.form["meses"])

        # taxa mensal por faixa
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

        flash("Investimento registado com sucesso!", "success")
        return redirect(url_for("investor_detail", investor_id=investor.id))

    return render_template("new_investment.html", investor=investor)


# -------------------------------------------------
# DELETAR INVESTIMENTO (somente admin)
# -------------------------------------------------

@app.route("/investimento/<int:investment_id>/deletar", methods=["POST"])
@require_roles("admin")
def delete_investment(investment_id):
    investment = Investment.query.get_or_404(investment_id)
    investor_id = investment.investor_id

    db.session.delete(investment)
    db.session.commit()

    flash("Investimento apagado com sucesso!", "info")
    return redirect(url_for("investor_detail", investor_id=investor_id))


# -------------------------------------------------
# ✅ MARCAR INVESTIMENTO COMO PAGO (TOTAL) (admin e gestor)
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

    flash("✅ Investimento marcado como PAGO (total) com sucesso!", "success")
    return redirect(url_for("investor_detail", investor_id=investment.investor_id))


# -------------------------------------------------
# ✅ DELETAR INVESTIDOR (somente admin)
# - Apaga também todos os investimentos do investidor
# -------------------------------------------------

@app.route("/investidor/<int:investor_id>/deletar", methods=["POST"])
@require_roles("admin")
def delete_investor(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    # apaga investimentos antes (evita erro de FK no Postgres)
    Investment.query.filter_by(investor_id=investor.id).delete(synchronize_session=False)

    db.session.delete(investor)
    db.session.commit()

    flash("Investidor apagado com sucesso!", "info")
    return redirect(url_for("dashboard"))


# -------------------------------------------------
# RELATÓRIOS GERAIS (leitura/gestor/admin)
# -------------------------------------------------

@app.route("/relatorios")
@require_roles("admin", "gestor", "leitura")
def relatorios():
    investments = Investment.query.all()
    investidores = Investor.query.all()
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
# EXPORTAR PARA EXCEL (admin e gestor)
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
# ADMIN: GERIR UTILIZADORES (somente admin)
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
    flash("Password atualizada com sucesso.", "success")
    return redirect(url_for("admin_users"))


# -------------------------------------------------
# RUN LOCAL
# -------------------------------------------------

if __name__ == "__main__":
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=debug)
