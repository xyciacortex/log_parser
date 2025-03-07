import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
import pandas as pd
import json
import re
from tkinter import messagebox
import json
import pyperclip
import platform


def load_patterns():
    """Load error and warning patterns from a JSON file."""
    try:
        with open("log_patterns.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print("⚠ Warning: log_patterns.json not found. Using default patterns.")
        return {"errors": ["error", "failed", "critical", "exception", "denied"], 
                "warnings": ["warning", "deprecated", "slow", "retry"]}

class LogParserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Parser V6.2")
        self.root.geometry("1700x800")
        self.patterns = load_patterns()  # Load patterns when the app starts

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

        self.outlier_button = tk.Button(button_frame, text="Find Outliers", command=self.find_outliers)
        self.outlier_button.pack(side=tk.LEFT, padx=5)

        # Create a frame to hold the Treeview and Log Details together
        content_frame = tk.Frame(root)
        content_frame.pack(expand=True, fill="both")

        # Create a frame for the Treeview and scrollbar (LOG LIST)
        tree_frame = tk.Frame(content_frame)
        tree_frame.pack(expand=True, fill="both", side=tk.TOP)

        # Create the Treeview
        self.tree = ttk.Treeview(tree_frame, selectmode="extended")  # Allows multiple row selection

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
        self.outliers = set()  # 🛠 Initialize empty set for outliers

        # **Move tag configurations INSIDE `__init__` AFTER `self.tree` is created**
        self.tree.tag_configure("error", background="red", foreground="white")
        self.tree.tag_configure("warning", background="yellow", foreground="black")
        self.tree.tag_configure("info", background="lightgreen", foreground="black")
        self.tree.tag_configure("outlier", background="orange", foreground="black")  # Highlight outliers

                # Bind selection events to show log details in the lower frame
        self.tree.bind("<ButtonRelease-1>", self.show_log_details)
        self.tree.bind("<KeyRelease-Up>", self.show_log_details)
        self.tree.bind("<KeyRelease-Down>", self.show_log_details)

        # Create a frame for the Notepad section
        notepad_frame = tk.Frame(self.root, relief=tk.RAISED, bd=2)
        notepad_frame.pack(expand=True, fill="both", padx=10, pady=5)

        # Create a toolbar for formatting inside the notepad frame
        toolbar_frame = tk.Frame(notepad_frame)
        toolbar_frame.pack(fill="x", padx=5, pady=3)

        # Toolbar buttons for text formatting (Icons can be added later)
        bold_icon = tk.Button(toolbar_frame, text="🅑", command=self.apply_bold, font=("Arial", 10, "bold"))
        bold_icon.pack(side=tk.LEFT, padx=5)

        italic_icon = tk.Button(toolbar_frame, text="𝑰", command=self.apply_italics, font=("Arial", 10, "italic"))
        italic_icon.pack(side=tk.LEFT, padx=5)

        highlight_icon = tk.Button(toolbar_frame, text="🟨", command=self.apply_highlight)
        highlight_icon.pack(side=tk.LEFT, padx=5)

        clear_icon = tk.Button(toolbar_frame, text="✖", command=self.clear_formatting)
        clear_icon.pack(side=tk.LEFT, padx=5)

        # Notepad area below the toolbar
        self.notepad = tk.Text(notepad_frame, height=8, wrap=tk.WORD)
        self.notepad.pack(expand=True, fill="both", padx=10, pady=5)

        # Define highlight color in RTF
        self.notepad.tag_configure("highlight", background="yellow", foreground="black")

        # Define text formatting tags
        self.notepad.tag_configure("bold", font=("TkDefaultFont", 10, "bold"))
        self.notepad.tag_configure("italic", font=("TkDefaultFont", 10, "italic"))
        self.notepad.tag_configure("highlight", background="yellow")

        # History stack for undo feature
        self.notepad_history = []

        # Undo button (placed on the toolbar)
        self.undo_button = tk.Button(button_frame, text="Undo", command=self.undo_last_entry, state=tk.NORMAL)
        self.undo_button.pack(side=tk.LEFT, padx=5)
        self.update_undo_button_state()  # Ensure correct initial state

        copy_button = tk.Button(toolbar_frame, text="📋 Copy", command=self.copy_to_clipboard)
        copy_button.pack(side=tk.LEFT, padx=5)

        # Buttons to manage the notepad
        self.save_to_notepad_button = tk.Button(button_frame, text="Save to Notepad", command=self.save_to_notepad)
        self.save_to_notepad_button.pack(side=tk.LEFT, padx=5)

        self.clear_notepad_button = tk.Button(button_frame, text="Clear Notepad", command=self.clear_notepad)
        self.clear_notepad_button.pack(side=tk.LEFT, padx=5)

        self.export_selected_button = tk.Button(button_frame, text="Export Selected", command=self.export_selected_logs)
        self.export_selected_button.pack(side=tk.LEFT, padx=5)        

    def save_to_notepad(self):
        """Save selected log rows to the notepad in JSON format."""
        selected_items = self.tree.selection()  # Get all selected rows
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select at least one log entry.")
            return

        logs_list = []  # Store logs as JSON objects

        for item in selected_items:
            row_values = self.tree.item(item, "values")
            if row_values:
                log_entry = {col: row_values[idx] for idx, col in enumerate(self.df.columns)}  # Create JSON entry
                logs_list.append(log_entry)

        if logs_list:
            current_text = self.notepad.get("1.0", tk.END).strip()
            try:
                existing_data = json.loads(current_text) if current_text else []
            except json.JSONDecodeError:
                existing_data = []  # If existing data is invalid, reset it

            existing_data.extend(logs_list)  # Append new logs to existing JSON

            formatted_json = json.dumps(existing_data, indent=2)  # Pretty print JSON
            self.notepad.delete("1.0", tk.END)
            self.notepad.insert(tk.END, formatted_json)

            self.notepad_history.append(logs_list)  # Track for undo
            self.update_undo_button_state()  # Enable Undo button

    def undo_last_entry(self):
        """Undo only the last added log entry while keeping JSON format valid."""
        if not self.notepad_history:
            return

        last_entries = self.notepad_history.pop()  # Get the last inserted log(s)

        current_text = self.notepad.get("1.0", tk.END).strip()
        try:
            existing_data = json.loads(current_text) if current_text else []
        except json.JSONDecodeError:
            existing_data = []  # Reset if data is corrupted

        # Remove the last added logs while preserving the rest
        for entry in last_entries:
            if entry in existing_data:
                existing_data.remove(entry)

        formatted_json = json.dumps(existing_data, indent=2)  # Keep JSON formatted
        self.notepad.delete("1.0", tk.END)
        self.notepad.insert(tk.END, formatted_json)

        self.update_undo_button_state()  # Update Undo button

    def clear_notepad(self):
        """Clear all entries from the notepad."""
        self.notepad.delete("1.0", tk.END)

    def export_selected_logs(self):
        """Export manually selected and edited logs from the notepad to a TXT file."""
        notepad_content = self.notepad.get("1.0", tk.END).strip()
        if not notepad_content:
            messagebox.showwarning("No Logs", "No logs to export. Please add logs to the notepad first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Save Selected Logs"
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(notepad_content)  # Save exactly as written, keeping formatting

                messagebox.showinfo("Success", f"Selected logs saved to {file_path}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file:\n{e}")

    def update_undo_button_state(self):
        """Update the Undo button color instead of removing the text."""
        if self.notepad_history:
            self.undo_button.config(state=tk.NORMAL, bg="SystemButtonFace", fg="black")  # Active
        else:
            self.undo_button.config(state=tk.NORMAL, bg="lightgray", fg="gray")  # Inactive, but text visible

    def apply_bold(self):
        """Apply bold formatting to selected text."""
        try:
            selected_text = self.notepad.tag_ranges(tk.SEL)  # Get selected text range
            if selected_text:
                self.notepad.tag_add("bold", selected_text[0], selected_text[1])
        except tk.TclError:
            pass  # No text selected, ignore

    def apply_italics(self):
        """Apply italics formatting to selected text."""
        try:
            selected_text = self.notepad.tag_ranges(tk.SEL)
            if selected_text:
                self.notepad.tag_add("italic", selected_text[0], selected_text[1])
        except tk.TclError:
            pass

    def apply_highlight(self):
        """Apply highlight (yellow background) to selected text."""
        try:
            selected_text = self.notepad.tag_ranges(tk.SEL)
            if selected_text:
                self.notepad.tag_add("highlight", selected_text[0], selected_text[1])
        except tk.TclError:
            pass

    def clear_formatting(self):
        """Remove all formatting from the notepad."""
        self.notepad.tag_remove("bold", "1.0", tk.END)
        self.notepad.tag_remove("italic", "1.0", tk.END)
        self.notepad.tag_remove("highlight", "1.0", tk.END)

    def copy_to_clipboard(self):
        """Copy plain text from the notepad to the clipboard."""
        try:
            text_content = self.notepad.get("1.0", tk.END).strip()
            if not text_content:
                messagebox.showwarning("Copy Error", "No text to copy!")
                return

            pyperclip.copy(text_content)  # Copy as plain text
            messagebox.showinfo("Copied!", "Text copied to clipboard successfully!")

        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy text: {e}")

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
        file_path = "/Users/mike/python_scripts/log_parser/accounts_w__tenant_ids.csv"
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

    def display_data(self, df, highlight_outliers=False):
        """Display logs in the treeview and highlight outliers when requested."""
        self.tree.delete(*self.tree.get_children())  # Clear existing logs
        self.tree["columns"] = list(df.columns)
        self.tree["show"] = "headings"

        for col in df.columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=200, anchor="w")

        for _, row in df.iterrows():
            values = [str(v) if pd.notna(v) else "" for v in row]  # Ensure no None values

            # If highlighting outliers, force "outlier" tag
            if highlight_outliers:
                tag = "outlier"
            else:
                tag = self.get_log_severity(values)

            self.tree.insert("", "end", values=values, tags=(tag,))

    def clean_log_message(self, message):
        """Remove timestamps, session IDs, and other unique elements from log messages."""
        message = str(message)

        # Remove ISO 8601 timestamps
        message = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z", "[TIMESTAMP]", message)

        # Remove UUIDs (Session IDs, etc.)
        message = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "[UUID]", message)

        # Remove IP addresses
        message = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]", message)

        return message

    def find_outliers(self):
        """Find outliers while filtering out short or generic log messages."""
        if self.df is None or "Message" not in self.df.columns:
            return

        # Clean log messages before counting
        self.df["Cleaned_Message"] = self.df["Message"].apply(self.clean_log_message)

        # Remove very short messages (e.g., generic "Request succeeded")
        self.df = self.df[self.df["Cleaned_Message"].str.len() > 20]  # Only logs with >20 chars

        # Count occurrences of cleaned log messages
        message_counts = self.df["Cleaned_Message"].value_counts()

        # Rarity threshold dynamically adjusted
        rarity_threshold = 2 if len(self.df) > 1000 else 3
        rare_messages = set(message_counts[message_counts < rarity_threshold].index)

        # Store outlier information
        self.outliers = rare_messages

        # Filter to show only rare messages
        outlier_df = self.df[self.df["Cleaned_Message"].isin(self.outliers)].copy()

        # Limit max number of results
        max_outliers = 50
        if len(outlier_df) > max_outliers:
            outlier_df = outlier_df.sample(n=max_outliers, random_state=42)

        # Display only outliers
        self.display_data(outlier_df, highlight_outliers=True)

    def is_outlier(self, row_values):
        """Check if a log message is an outlier (rare occurrence)."""
        message_index = list(self.df.columns).index("Message")
        message = row_values[message_index]
        return message in self.outliers

    def get_log_severity(self, row_values):
        """Determine log severity based on message content while avoiding false matches."""
        
        # Convert row values to lowercase and join into a single string (excluding "Date")
        column_names = list(self.df.columns)
        filtered_columns = [col for col in column_names if col != "Date"]  # Exclude "Date"
        
        message = " ".join(str(row_values[column_names.index(col)]).lower() for col in filtered_columns)

        # Load patterns from log_patterns.json
        error_patterns = self.patterns["errors"]
        warning_patterns = self.patterns["warnings"]
        status_codes = self.patterns.get("status_codes", [])

        # 🔹 Check for exact status codes using word boundaries (avoiding false matches)
        for code in status_codes:
            if re.search(rf"\b{code}\b", message):  # Ensures '404' doesn't match '24454'
                return "error" if int(code) >= 400 else "warning"

        # 🔹 Check for regular errors and warnings (avoiding "Date" column)
        if any(keyword in message for keyword in error_patterns):
            return "error"
        elif any(keyword in message for keyword in warning_patterns):
            return "warning"

        return "info"

    def search_logs(self):
        search_text = self.search_var.get().lower()
        if not search_text or self.df is None:
            return

        # Split search text into multiple keywords (for AND search)
        keywords = search_text.split()

        # Exclude "Date" column from search
        search_columns = [col for col in self.df.columns if col != "Date"]

        # Apply search condition to all columns except Date
        filtered_df = self.df[
            self.df.apply(lambda row: all(
                any(keyword in str(row[col]).lower() for col in search_columns) for keyword in keywords
            ), axis=1)
        ]
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
        selected_item = self.tree.focus()  # Get selected row ID
        if not selected_item or self.df is None:
            return

        row_values = self.tree.item(selected_item, "values")  # Get row data
        service_index = list(self.df.columns).index("Service")

        if len(row_values) > service_index:
            selected_service = row_values[service_index]  # Get the selected service
            selected_date = row_values[0]  # Assuming the Date is the first column

            # Filter logs by selected service
            filtered_df = self.df[self.df["Service"] == selected_service].sort_values(by=["Date"], ascending=True)

            # Update the display with filtered data
            self.display_data(filtered_df)

            # Reselect the previously selected log in the filtered list
            for item in self.tree.get_children():
                item_values = self.tree.item(item, "values")
                if item_values and item_values[0] == selected_date:  # Match by Date
                    self.tree.selection_set(item)
                    self.tree.focus(item)
                    self.show_log_details(None)  # Ensure log details update
                    break

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
        """Reset the log view to show all logs again."""
        if self.original_df is not None:
            self.df = self.original_df.copy()
            self.outliers = set()  # Clear outliers
            self.display_data(self.df)  # Show everything again

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
            return  

        row_values = self.tree.item(selected_item, "values")  # Get row data
        if not row_values:
            return  

        try:
            # Identify the correct column index for "Message"
            message_index = list(self.df.columns).index("Message")
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

            # 🔹 Ensure Log Message Frame is **Read-Only**
            self.log_details.configure(state=tk.NORMAL)  # Temporarily enable
            self.log_details.delete("1.0", tk.END)
            self.log_details.insert(tk.END, message)
            self.log_details.configure(state=tk.DISABLED)  # 🔒 Disable editing after inserting

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