from datetime import datetime, timedelta

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
import io
import pandas as pd

# -------------------------------------------------
# CONFIGURAÇÃO BÁSICA
# -------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "troca_esta_frase_por_uma_chave_secreta_grande"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ukamba.db"
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
    role = db.Column(db.String(20), default="gestor")  # admin | gestor | leitura

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


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
# HELPERS DE PERMISSÃO
# -------------------------------------------------

def is_admin():
    return current_user.is_authenticated and current_user.role == "admin"


def admin_required(func):
    # decorador simples
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not is_admin():
            flash("Apenas administradores podem aceder a esta página.", "danger")
            return redirect(url_for("dashboard"))
        return func(*args, **kwargs)

    return wrapper


# -------------------------------------------------
# ROTAS DE AUTENTICAÇÃO
# -------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
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
    # se já estiver logado, manda direto para o dashboard
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    # se não estiver logado, mostra página inicial (landing page)
    return render_template("home.html")


# -------------------------------------------------
# DASHBOARD E INVESTIDORES
# -------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    # Listar todos os investidores
    investidores = Investor.query.all()

    # Listar todos os investimentos
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


# --------- ROTA COMPATÍVEL "UKAMBA" (CORRIGE O ERRO DO url_for('ukamba')) ---------

@app.route("/ukamba")
@login_required
def ukamba():
    # Qualquer link antigo que aponte para 'ukamba' cai aqui
    # e é redirecionado para o dashboard.
    return redirect(url_for("dashboard"))


@app.route("/investidor/<int:investor_id>")
@login_required
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


# --------- RELATÓRIO / COMPROVATIVO POR INVESTIDOR ---------

@app.route("/investidor/<int:investor_id>/relatorio")
@login_required
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
# NOVO INVESTIDOR / NOVO INVESTIMENTO
# -------------------------------------------------

@app.route("/novo_investidor", methods=["GET", "POST"])
@login_required
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
@login_required
def new_investment(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    if request.method == "POST":
        plano = request.form["plano"]

        # valor investido
        valor_investido = float(request.form["valor_investido"])
        meses = int(request.form["meses"])

        # -----------------------------
        # DEFINIÇÃO DA TAXA MENSAL POR FAIXA
        # -----------------------------
        if valor_investido >= 1_000_000:
            taxa_mensal = 0.03      # 3% ao mês
        elif 500_000 <= valor_investido <= 999_999:
            taxa_mensal = 0.025     # 2,5% ao mês
        elif 100_000 <= valor_investido <= 499_999:
            taxa_mensal = 0.02      # 2% ao mês
        else:
            flash("Valor mínimo para investimento é 100.000 Kz.", "danger")
            return redirect(url_for("new_investment", investor_id=investor.id))

        # juros compostos: taxa total no período
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
# DELETAR INVESTIMENTO
# -------------------------------------------------

@app.route("/investimento/<int:investment_id>/deletar", methods=["POST"])
@login_required
def delete_investment(investment_id):
    investment = Investment.query.get_or_404(investment_id)
    investor_id = investment.investor_id

    db.session.delete(investment)
    db.session.commit()
    flash("Investimento apagado com sucesso!", "info")

    # volta para a página do investidor dono do investimento
    return redirect(url_for("investor_detail", investor_id=investor_id))


# -------------------------------------------------
# RELATÓRIOS GERAIS
# -------------------------------------------------

@app.route("/relatorios")
@login_required
def relatorios():
    investments = Investment.query.all()
    investidores = Investor.query.all()
    hoje = datetime.utcnow().date()

    # --- Totais gerais ---
    total_investido = sum(inv.valor_investido for inv in investments)
    total_reembolsado = sum(inv.valor_reembolsado for inv in investments)
    total_a_recuperar = sum(inv.valor_em_falta() for inv in investments)

    # montante em atraso
    total_atrasado = sum(
        inv.valor_em_falta() for inv in investments if inv.esta_atrasado()
    )

    # investimentos ativos (ainda há valor em falta)
    investimentos_ativos = [inv for inv in investments if inv.valor_em_falta() > 0]
    num_investimentos_ativos = len(investimentos_ativos)

    # nº de investidores e ticket médio
    num_investidores = len(investidores)
    media_por_investidor = (
        total_investido / num_investidores if num_investidores > 0 else 0
    )

    # percentagem já recuperada em relação ao total previsto (capital+juros)
    total_previsto = sum(inv.valor_total_a_receber() for inv in investments)
    perc_recuperado = (
        (total_reembolsado / total_previsto) * 100 if total_previsto > 0 else 0
    )

    # --- Listas especiais ---
    investimentos_atrasados = [inv for inv in investments if inv.esta_atrasado()]
    a_vencer_30_dias = [
        inv
        for inv in investments
        if 0 <= (inv.data_fim - hoje).days <= 30 and inv.valor_em_falta() > 0
    ]

    # --- Resumo por investidor ---
    resumo_investidores = []
    for invs in investidores:
        invs_investments = [i for i in investments if i.investor_id == invs.id]
        if not invs_investments:
            continue

        valor_investido_inv = sum(i.valor_investido for i in invs_investments)
        valor_reembolsado_inv = sum(i.valor_reembolsado for i in invs_investments)
        valor_em_falta_inv = sum(i.valor_em_falta() for i in invs_investments)
        atrasado_inv = any(i.esta_atrasado() for i in invs_investments)

        resumo_investidores.append(
            {
                "investor": invs,
                "qtd": len(invs_investments),
                "valor_investido": valor_investido_inv,
                "valor_reembolsado": valor_reembolsado_inv,
                "valor_em_falta": valor_em_falta_inv,
                "atrasado": atrasado_inv,
            }
        )

    return render_template(
        "relatorios.html",
        # totais principais
        total_investido=total_investido,
        total_reembolsado=total_reembolsado,
        total_a_recuperar=total_a_recuperar,
        total_atrasado=total_atrasado,
        num_investimentos_ativos=num_investimentos_ativos,
        num_investidores=num_investidores,
        media_por_investidor=media_por_investidor,
        perc_recuperado=perc_recuperado,
        # listas
        investimentos_atrasados=investimentos_atrasados,
        a_vencer_30_dias=a_vencer_30_dias,
        resumo_investidores=resumo_investidores,
    )


# -------------------------------------------------
# EXPORTAR PARA EXCEL
# -------------------------------------------------

@app.route("/exportar/excel")
@login_required
def exportar_excel():
    investments = Investment.query.all()

    dados = []
    for inv in investments:
        dados.append(
            {
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
            }
        )

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
# APP (CRIA BD E USUÁRIO ADMIN)
# -------------------------------------------------

if __name__ == "__main__":
    with app.app_context():
        # cria as tabelas se ainda não existirem
        db.create_all()

        # Verifica se já existe usuário admin
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                role="admin",
            )
            admin.set_password("123456")
            db.session.add(admin)
            db.session.commit()
            print("Usuário admin criado com sucesso: admin / 123456")
        else:
            print("Usuário admin já existe.")

    app.run(debug=True)
