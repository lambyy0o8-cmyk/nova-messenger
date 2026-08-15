* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: #0f1115;
  color: #e7e9ec;
  min-height: 100vh;
}

.hidden { display: none !important; }

/* Вход */
.admin-login {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.admin-login-card {
  width: 100%;
  max-width: 340px;
  background: #171a21;
  border: 1px solid #262a33;
  border-radius: 16px;
  padding: 28px 24px;
  text-align: center;
}
.admin-logo {
  width: 52px;
  height: 52px;
  margin: 0 auto 14px;
  border-radius: 14px;
  background: linear-gradient(135deg, #2AABEE, #229ED9);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
}
.admin-login-card h1 { font-size: 18px; margin: 0 0 8px; }
.admin-hint { font-size: 12.5px; color: #8b93a1; margin: 0 0 18px; line-height: 1.4; }
.admin-hint code { background: #22262f; padding: 1px 5px; border-radius: 4px; }

.admin-login-card input {
  width: 100%;
  padding: 11px 12px;
  border-radius: 10px;
  border: 1.5px solid #2b303a;
  background: #12141a;
  color: #e7e9ec;
  font-size: 14px;
  outline: none;
  margin-bottom: 10px;
}
.admin-login-card input:focus { border-color: #2AABEE; }

.admin-login-card button {
  width: 100%;
  padding: 11px;
  border: none;
  border-radius: 10px;
  background: linear-gradient(135deg, #2AABEE, #229ED9);
  color: white;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
}
.admin-login-card button:disabled { opacity: .6; cursor: default; }

.admin-error {
  margin-top: 12px;
  font-size: 13px;
  color: #f16e6e;
}

/* Панель */
.admin-panel { max-width: 720px; margin: 0 auto; padding: 24px 18px 60px; }
.admin-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 18px;
  flex-wrap: wrap;
}
.admin-header h1 { font-size: 20px; margin: 0; }
.admin-header-actions { display: flex; gap: 8px; align-items: center; }
.admin-header-actions input {
  padding: 9px 12px;
  border-radius: 10px;
  border: 1.5px solid #2b303a;
  background: #171a21;
  color: #e7e9ec;
  font-size: 13.5px;
  outline: none;
  min-width: 220px;
}
.admin-header-actions input:focus { border-color: #2AABEE; }
.admin-header-actions button {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  border: 1.5px solid #2b303a;
  background: #171a21;
  color: #e7e9ec;
  font-size: 16px;
  cursor: pointer;
}

.admin-empty { color: #8b93a1; font-size: 14px; padding: 20px 4px; }

.admin-list { display: flex; flex-direction: column; gap: 8px; }
.admin-row {
  display: flex;
  align-items: center;
  gap: 12px;
  background: #171a21;
  border: 1px solid #262a33;
  border-radius: 12px;
  padding: 10px 14px;
}
.admin-avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  font-weight: 700;
  color: white;
}
.admin-row-meta { flex: 1; min-width: 0; }
.admin-row-name {
  font-size: 14.5px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.admin-row-sub { font-size: 12.5px; color: #8b93a1; margin-top: 2px; }

.verified-badge { width: 15px; height: 15px; fill: #2AABEE; flex: 0 0 auto; }

/* Переключатель */
.admin-switch { position: relative; display: inline-block; width: 42px; height: 24px; flex: 0 0 auto; }
.admin-switch input { opacity: 0; width: 0; height: 0; }
.admin-slider {
  position: absolute; inset: 0; cursor: pointer;
  background: #2b303a; border-radius: 24px; transition: .15s;
}
.admin-slider::before {
  content: ""; position: absolute; height: 18px; width: 18px;
  left: 3px; top: 3px; background: white; border-radius: 50%; transition: .15s;
}
.admin-switch input:checked + .admin-slider { background: #2AABEE; }
.admin-switch input:checked + .admin-slider::before { transform: translateX(18px); }