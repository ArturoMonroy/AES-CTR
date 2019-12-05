# AES CTR y AES CBC-PKC7 compatible con PKCS5Padding (Java)

Obtiene una DLL y expone los metodos, al estilo de C++ stdcall (Pero mas sencillo ;)).

Tiene metodos estaticos, ademas de crear un objeto y usarlo Thread-Safe

Gets a DLL and export methos like C++ stdcall (but easier ;) ).

Static methods, also can create a instance (using interface) to thread-safe use

>Por supuesto la DLL puede usarse con cualquier lenguaje/Of course you can use with any language 

### Delphi example

## vars and types

_TEncriptaNTS     = function  (const base64Data : PChar ; const llave : PChar; out base64Resultado : WideString ): Integer; stdcall;
_TDesencriptaNTS  = function  (const base64Data : PChar;  const llave : PChar; out resultado : WideString ): Integer; stdcall;
_TVersionNTS      = procedure ( out v : WideString ) ; stdcall;


IAES_CBC_PKC7 = interface(IUnknown)
['{9971C5E0-B296-4AB8-AEE7-F2553BACB730}']
  function  Encripta     ( const base64Data : WideString; const llave : WideString; out base64Resultado : WideString ): Integer; safecall;
  function  Desencripta  ( const base64Data : WideString; const llave : WideString; out resultado : WideString ): Integer; safecall;
  function  GetID        ():WideString; safecall;
  procedure SetID        ( const v : WideString);safecall;
  function  Version      ():WideString; safecall;

  //
  property ID: WideString read GetID write SetID;
end;

_TCreaObjeto_CBC_PKC7      = procedure ( out AES_CBC_PKC7: IAES_CBC_PKC7); stdcall;

## Cargar DLL y metodo /Load DLL and function 
``` 
_Handle_:= LoadLibrary('PinBlockDLL.dll');
  if _Handle_ <> 0 then
    _F_PINBlockDLL:= GetProcAddress(_Handle_, 'PINBlock');
