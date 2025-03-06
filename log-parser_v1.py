import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
import pandas as pd
import json
import re

class LogParserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Parser")
        self.root.geometry("1000x600")
        
        # Load tenant mapping
        self.tenant_mapping = self.load_tenant_mapping()
        
        # Frame for buttons to align in a single row
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10, fill='x')
        
        self.load_button = tk.Button(button_frame, text="Load CSV", command=self.load_csv)
        self.load_button.pack(side=tk.LEFT, padx=5)
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(button_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        self.search_button = tk.Button(button_frame, text="Search", command=self.search_logs)
        self.search_button.pack(side=tk.LEFT, padx=5)
        
        self.tenant_var = tk.StringVar()
        self.tenant_dropdown = ttk.Combobox(button_frame, textvariable=self.tenant_var, state='readonly')
        self.tenant_dropdown.pack(side=tk.LEFT, padx=5)
        self.tenant_dropdown.bind("<<ComboboxSelected>>", self.select_tenant_logs)
        
        self.follow_service_button = tk.Button(button_frame, text="Follow Service", command=self.follow_service_logs)
        self.follow_service_button.pack(side=tk.LEFT, padx=5)
        
        self.follow_host_button = tk.Button(button_frame, text="Follow Host", command=self.follow_host_logs)
        self.follow_host_button.pack(side=tk.LEFT, padx=5)
        
        self.reset_button = tk.Button(button_frame, text="Reset Filters", command=self.reset_logs)
        self.reset_button.pack(side=tk.LEFT, padx=5)
        
        self.tree = ttk.Treeview(root)
        self.tree.pack(expand=True, fill="both")
        self.tree.bind("<ButtonRelease-1>", self.show_log_details)
        self.tree.bind("<KeyRelease-Up>", self.show_log_details)
        self.tree.bind("<KeyRelease-Down>", self.show_log_details)
        
        self.log_details = scrolledtext.ScrolledText(root, height=10, wrap=tk.WORD)
        self.log_details.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.sort_order = {}  # Dictionary to store sort state
        self.df = None  # Placeholder for dataframe
        self.original_df = None  # Store original data
        self.selected_log = None  # Store selected log entry
        self.selected_log_index = None  # Store selected log index
    
    def load_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.df = pd.read_csv(file_path, dtype=str)
            self.df["Tenant"] = self.df["Message"].apply(self.extract_tenant)
            self.original_df = self.df.copy()
            self.display_data(self.df)
            self.update_tenant_dropdown()
    
    def load_tenant_mapping(self):
        """Load tenant mapping from a CSV file."""
        file_path = "/Users/mike/Downloads/accounts_w__tenant_ids.csv"  # Update with actual path
        try:
            df = pd.read_csv(file_path, dtype=str)
            df.columns = df.columns.str.strip()
            print("Columns in tenant mapping file:", df.columns.tolist())
            
            if "Tenant ID" in df.columns and "Account Name" in df.columns:
                return dict(zip(df["Tenant ID"], df["Account Name"]))
            else:
                print("Tenant ID or Account Name column not found in CSV.")
                return {}
        except FileNotFoundError:
            print("Tenant mapping file not found.")
            return {}


    def display_data(self, df):
        self.tree.delete(*self.tree.get_children())
        
        self.tree["columns"] = list(df.columns)
        self.tree["show"] = "headings"
        
        for col in df.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200, anchor="w")
        
        for _, row in df.iterrows():
            self.tree.insert("", "end", values=list(row))
    
    def search_logs(self):
        search_text = self.search_var.get().lower()
        if self.df is None:
            return
        
        filtered_df = self.df[self.df.apply(lambda row: row.astype(str).str.lower().str.contains(search_text, na=False).any(), axis=1)]
        self.display_data(filtered_df)
    
    def select_tenant_logs(self, event):
        selected_tenant = self.tenant_var.get()
        if self.df is None or selected_tenant == "Select Tenant":
            return
        
        filtered_df = self.df[self.df["Tenant"] == selected_tenant]
        self.display_data(filtered_df)
    
    def extract_tenant(self, message):
        match = re.search(r"tenant \[(\d+)\]", str(message))
        return match.group(1) if match else "Unknown"

    def follow_service_logs(self):
        """Filters logs to show only those matching the selected service."""
        selected_item = self.tree.focus()
        if not selected_item or self.df is None:
            return
        
        row_values = self.tree.item(selected_item, "values")
        service_index = list(self.df.columns).index("Service")
        service = row_values[service_index] if len(row_values) > service_index else ""
        
        if service:
            filtered_df = self.df[self.df["Service"] == service].sort_values(by=["Date"], ascending=True)
            self.display_data(filtered_df)


    def update_tenant_dropdown(self):
        if self.df is not None and "Tenant" in self.df.columns:
            tenant_ids = sorted(self.df["Tenant"].dropna().astype(str).unique())
            tenant_names = [self.tenant_mapping.get(tid, tid) for tid in tenant_ids]
            self.tenant_dropdown["values"] = tenant_names
            if tenant_names:
                self.tenant_var.set(tenant_names[0])  # Set the first tenant as default
        else:
            self.tenant_dropdown["values"] = []

    def reset_logs(self):
        """Reset the log view to the original unfiltered state."""
        if self.original_df is not None:
            self.df = self.original_df.copy()
            self.display_data(self.df)


    def follow_host_logs(self):
        """Filter logs to follow the selected host."""
        selected_item = self.tree.focus()
        if not selected_item or self.df is None:
            return

        row_values = self.tree.item(selected_item, "values")
        host_index = list(self.df.columns).index("Host")
        host = row_values[host_index] if len(row_values) > host_index else ""

        if host:
            filtered_df = self.df[self.df["Host"] == host].sort_values(by=["Date"], ascending=True)
            self.display_data(filtered_df)

    
    def load_tenant_mapping(self):
        file_path = "/Users/mike/Downloads/accounts_w__tenant_ids.csv"  # Update with actual path
        try:
            df = pd.read_csv(file_path, dtype=str)
            df.columns = df.columns.str.strip()
            print("Columns in tenant mapping file:", df.columns.tolist())
            
            if "Tenant ID" in df.columns and "Account Name" in df.columns:
                return dict(zip(df["Tenant ID"], df["Account Name"]))
            else:
                print("Tenant ID or Account Name column not found in CSV.")
                return {}
        except FileNotFoundError:
            print("Tenant mapping file not found.")
            return {}
    
    def show_log_details(self, event):
        selected_item = self.tree.focus()
        if not selected_item:
            return
        
        row_values = self.tree.item(selected_item, "values")
        message = row_values[-1] if row_values else ""
        
        if isinstance(message, str) and message.startswith("{") and message.endswith("}"):
            try:
                message = json.dumps(json.loads(message), indent=2)
            except json.JSONDecodeError:
                pass
        
        self.log_details.delete("1.0", tk.END)
        self.log_details.insert(tk.END, message)
    
if __name__ == "__main__":
    root = tk.Tk()
    app = LogParserApp(root)
    root.mainloop()