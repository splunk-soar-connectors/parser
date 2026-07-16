**Unreleased**

* Upgraded to pdfminer.six 20260107.post1 and added Python 3.13 compatibility.
* Fix email IOC patterns to use bounded matching on untrusted input.
* Handle recursive email parser failures without escaping the connector action.
* Build PDF xref XML with fragment lists to avoid quadratic string copying.
* Extract internationalized URLs so IDN homograph indicators are not missed.
* Extract prose URLs alongside HTML links and normalize browser-clickable whitespace.
