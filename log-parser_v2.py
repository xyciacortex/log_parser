import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
import pandas as pd
import json
import re
from tkinter import messagebox

class LogParserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Parser V3")
        self.root.geometry("1700x800")
        
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
        
        # Create a frame to hold the Treeview and Log Details together
        content_frame = tk.Frame(root)
        content_frame.pack(expand=True, fill="both")

        # Create a frame for the Treeview and scrollbar (LOG LIST)
        tree_frame = tk.Frame(content_frame)
        tree_frame.pack(expand=True, fill="both", side=tk.TOP)

        # Create the Treeview
        self.tree = ttk.Treeview(tree_frame)

        # Create a vertical scrollbar and attach it to the tree
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scrollbar.set)

        # Pack the Treeview and its scrollbar together (Taking the Top Half)
        self.tree.pack(expand=True, fill="both", side=tk.LEFT)
        tree_scrollbar.pack(fill="y", side=tk.RIGHT)

        # Create the Log Details window (Taking the Bottom Half)
        self.log_details = scrolledtext.ScrolledText(content_frame, height=10, wrap=tk.WORD)
        self.log_details.pack(expand=True, fill="both", padx=10, pady=10)

        self.sort_order = {}  # Dictionary to store sort state
        self.df = None  # Placeholder for dataframe
        self.original_df = None  # Store original data

                # Bind selection events to show_log_details
        self.tree.bind("<ButtonRelease-1>", self.show_log_details)
        self.tree.bind("<KeyRelease-Up>", self.show_log_details)
        self.tree.bind("<KeyRelease-Down>", self.show_log_details)


    def load_csv(self):
        """Load logs from a CSV file, extract Tenant IDs, and replace them with Account Names."""
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.df = pd.read_csv(file_path, dtype=str, header=0)  # Read CSV with headers
            
            # Extract Tenant IDs from the "Message" field
            self.df["Tenant"] = self.df["Message"].apply(self.extract_tenant)

            # Replace Tenant IDs with Account Names using the mapping
            self.df["Tenant"] = self.df["Tenant"].apply(lambda tid: self.tenant_mapping.get(tid, tid if tid else "Unknown"))

            self.original_df = self.df.copy()
            self.display_data(self.df)
            self.update_tenant_dropdown()


    def load_tenant_mapping(self):
        """Load tenant mapping from a CSV file to map Tenant ID to Account Name, with debug logging."""
        file_path = "/Users/mike/Downloads/accounts_w__tenant_ids.csv"
        try:
            print(f"\n=== Loading Tenant Mapping from: {file_path} ===\n")

            df = pd.read_csv(file_path, dtype=str, encoding='utf-8-sig', quotechar='"')

            print("Raw DataFrame:\n", df.head())

            print(f"\nDetected columns: {df.columns.tolist()}\n")

            if df.shape[1] != 2:
                print(f"ERROR: Expected 2 columns, but found {df.shape[1]}. Possible format issue.")
                return {}

            expected_columns = ["Account Name", "Tenant ID"]
            actual_columns = df.columns.tolist()

            if actual_columns != expected_columns:
                print(f"WARNING: Column names do not match expected names!")
                print(f"Expected: {expected_columns}")
                print(f"Found: {actual_columns}")
                print("\nAttempting to rename columns...\n")
                df.columns = expected_columns

            print("\nDataFrame after renaming columns:\n", df.head())

            tenant_mapping = dict(zip(df["Tenant ID"], df["Account Name"]))

            print("\n=== First 10 Mapped Entries ===")
            for key, value in list(tenant_mapping.items())[:10]:
                print(f"Tenant ID: {key} --> Account Name: {value}")

            # Store the mapping in the class variable
            self.tenant_mapping = tenant_mapping

            # *** Explicitly update the dropdown after loading ***
            self.update_tenant_dropdown()

            return tenant_mapping

        except FileNotFoundError:
            print("ERROR: Tenant mapping file not found.")
            return {}
        except pd.errors.ParserError as e:
            print(f"ERROR: CSV parsing issue - {e}")
            return {}
        except Exception as e:
            print(f"Unexpected error: {e}")
            return {}

    def display_data(self, df):
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = list(df.columns)
        self.tree["show"] = "headings"

        for col in df.columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=200, anchor="w")

        for _, row in df.iterrows():
            values = list(row)
            tag = self.get_log_severity(values)  # Determine row color
            self.tree.insert("", "end", values=values, tags=(tag,))

        # Define tag styles
        self.tree.tag_configure("error", background="red", foreground="white")
        self.tree.tag_configure("warning", background="yellow", foreground="black")
        self.tree.tag_configure("info", background="lightgreen", foreground="black")

    def get_log_severity(self, row_values):
        """Determine log severity based on message content."""
        message = " ".join(str(value).lower() for value in row_values)  # Convert all row values to lowercase
        
        # Improved error detection logic
        if any(keyword in message for keyword in ["error", "failed", "critical", "exception", "denied"]):
            return "error"
        elif any(keyword in message for keyword in ["warning", "deprecated", "slow", "retry"]):
            return "warning"
        return "info"

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
        """Extract Tenant ID from message field, returning empty string if not found."""
        match = re.search(r"tenant \[(\d+)\]", str(message))
        return match.group(1) if match else ""

    def follow_service_logs(self):
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
        """Update the dropdown to display Account Names instead of Tenant IDs."""
        if not hasattr(self, 'df') or self.df is None:
            print("Skipping tenant dropdown update: No logs loaded yet.")
            return  # Exit if logs are not loaded

        if self.tenant_mapping:
            tenant_names = sorted(self.tenant_mapping.values())  # Get list of account names
            print("Updating Tenant Dropdown with values:", tenant_names)  # Debugging output
            self.tenant_dropdown["values"] = tenant_names  # Populate dropdown with Account Names
            self.tenant_var.set("Select Tenant") if tenant_names else self.tenant_var.set("")
        else:
            print("No tenants found to update dropdown.")
            self.tenant_dropdown["values"] = []

    def reset_logs(self):
        """Reset the log view to the original unfiltered state."""
        if self.original_df is not None:
            self.df = self.original_df.copy()
            self.display_data(self.df)

    def follow_host_logs(self):
        selected_item = self.tree.focus()
        if not selected_item or self.df is None:
            return

        row_values = self.tree.item(selected_item, "values")
        host_index = list(self.df.columns).index("Host")
        host = row_values[host_index] if len(row_values) > host_index else ""

        if host:
            filtered_df = self.df[self.df["Host"] == host].sort_values(by=["Date"], ascending=True)
            self.display_data(filtered_df)

    def show_log_details(self, event):
        selected_item = self.tree.focus()  # Get selected row
        if not selected_item:
            print("No row selected.")
            return  

        row_values = self.tree.item(selected_item, "values")  # Get row data
        if not row_values:
            print("No data found for selected row.")
            return  

        print(f"Selected Row Data: {row_values}")  # Debugging

        try:
            # Manually set the correct column index for "Message"
            message_index = 3  # "Message" is the 4th column, so index is 3
            if len(row_values) > message_index:
                message = row_values[message_index]
            else:
                message = "Message column out of range."

            # Format JSON logs properly
            if isinstance(message, str) and message.startswith("{") and message.endswith("}"):
                try:
                    message = json.dumps(json.loads(message), indent=2)
                except json.JSONDecodeError:
                    pass  

            print(f"Extracted Message: {message}")  # Debugging

            # Display the log message in the text area
            self.log_details.delete("1.0", tk.END)
            self.log_details.insert(tk.END, message)

        except Exception as e:
            print(f"Error displaying log details: {e}")

    def sort_column(self, col):
        """Sort columns when clicking headers."""
        ascending = self.sort_order.get(col, True)
        self.df = self.df.sort_values(by=[col], ascending=ascending)
        self.sort_order[col] = not ascending
        self.display_data(self.df)

if __name__ == "__main__":
    root = tk.Tk()
    app = LogParserApp(root)
    root.mainloop()