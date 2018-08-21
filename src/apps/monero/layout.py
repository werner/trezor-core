from trezor import ui
from trezor.messages import ButtonRequestType
from trezor.ui.text import Text
from trezor.utils import chunks

from apps.common.confirm import require_confirm, require_hold_to_confirm


async def require_confirm_watchkey(ctx):
    content = Text("Confirm export", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal(*["Do you really want to", "export watch-only", "credentials?"])
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_keyimage_sync(ctx):
    content = Text("Confirm ki sync", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal(*["Do you really want to", "sync key images?"])
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)


async def require_confirm_tx_plain(ctx, to, value, is_change=False):
    content = Text(
        "Confirm " + ("sending" if not is_change else "change"),
        ui.ICON_SEND,
        icon_color=ui.GREEN,
    )
    content.bold(format_amount(value))
    content.normal("to")
    content.mono(*split_address(to))
    return await require_confirm(ctx, content, code=ButtonRequestType.SignTx)


def paginate_lines(lines, lines_per_page=5):
    pages = []
    cpage = []
    nlines = 0
    last_modifier = None
    for line in lines:
        cpage.append(line)
        if not isinstance(line, int):
            nlines += 1
        else:
            last_modifier = line

        if nlines >= lines_per_page:
            pages.append(cpage)
            cpage = []
            nlines = 0
            if last_modifier is not None:
                cpage.append(last_modifier)

    if nlines > 0:
        pages.append(cpage)
    return pages


@ui.layout
async def tx_dialog(
    ctx,
    code,
    content,
    cancel_btn,
    confirm_btn,
    cancel_style,
    confirm_style,
    scroll_tuple=None,
):
    from trezor.messages import MessageType
    from trezor.messages.ButtonRequest import ButtonRequest
    from trezor.ui.confirm import ConfirmDialog
    from trezor.ui.scroll import Scrollpage

    await ctx.call(ButtonRequest(code=code), MessageType.ButtonAck)
    dialog = ConfirmDialog(
        content,
        cancel=cancel_btn,
        confirm=confirm_btn,
        cancel_style=cancel_style,
        confirm_style=confirm_style,
    )

    if scroll_tuple and scroll_tuple[1] > 1:
        dialog = Scrollpage(dialog, scroll_tuple[0], scroll_tuple[1])

    return await ctx.wait(dialog)


async def naive_pagination(
    ctx, lines, title, icon=ui.ICON_RESET, icon_color=ui.ORANGE, per_page=5
):
    from trezor import res
    from trezor.ui.confirm import CANCELLED, CONFIRMED, DEFAULT_CANCEL, DEFAULT_CONFIRM

    if isinstance(lines, (list, tuple)):
        lines = lines
    else:
        lines = list(chunks(lines, 16))

    pages = paginate_lines(lines, per_page)
    npages = len(pages)
    cur_step = 0
    code = ButtonRequestType.SignTx
    iback = res.load(ui.ICON_BACK)
    inext = res.load(ui.ICON_CLICK)

    while cur_step <= npages:
        text = pages[cur_step]
        fst_page = cur_step == 0
        lst_page = cur_step + 1 >= npages

        cancel_btn = DEFAULT_CANCEL if fst_page else iback
        cancel_style = ui.BTN_CANCEL if fst_page else ui.BTN_DEFAULT
        confirm_btn = DEFAULT_CONFIRM if lst_page else inext
        confirm_style = ui.BTN_CONFIRM if lst_page else ui.BTN_DEFAULT

        paging = ("%d/%d" % (cur_step + 1, npages)) if npages > 1 else ""
        content = Text("%s %s" % (title, paging), icon, icon_color=icon_color)
        content.normal(*text)

        # render_scrollbar(cur_step, npages)
        reaction = await tx_dialog(
            ctx,
            code,
            content,
            cancel_btn,
            confirm_btn,
            cancel_style,
            confirm_style,
            (cur_step, npages),
        )

        if fst_page and reaction == CANCELLED:
            return False
        elif not lst_page and reaction == CONFIRMED:
            cur_step += 1
        elif lst_page and reaction == CONFIRMED:
            return True
        elif reaction == CANCELLED:
            cur_step -= 1
        elif reaction == CONFIRMED:
            cur_step += 1


async def require_confirm_payment_id(ctx, payment_id):
    from ubinascii import hexlify
    from trezor import wire

    if not await naive_pagination(
        ctx,
        [ui.MONO] + list(chunks(hexlify((payment_id)), 16)),
        "Payment ID",
        ui.ICON_SEND,
        ui.GREEN,
    ):
        raise wire.ActionCancelled("Cancelled")


async def require_confirm_tx(ctx, to, value, is_change=False):
    len_addr = (len(to) + 15) // 16
    if len_addr <= 2:
        return await require_confirm_tx_plain(ctx, to, value, is_change)

    else:
        to_chunks = list(split_address(to))
        from trezor import wire

        text = [ui.BOLD, format_amount(value), ui.MONO] + to_chunks

        conf_text = "Confirm send" if not is_change else "Con. change"
        if not await naive_pagination(ctx, text, conf_text, ui.ICON_SEND, ui.GREEN, 4):
            raise wire.ActionCancelled("Cancelled")


async def require_confirm_fee(ctx, fee):
    content = Text("Confirm fee", ui.ICON_SEND, icon_color=ui.GREEN)
    content.bold(format_amount(fee))
    await require_hold_to_confirm(ctx, content, ButtonRequestType.ConfirmOutput)


@ui.layout
async def simple_wait(tm):
    from trezor import loop

    await loop.sleep(tm)


async def light_on():
    from trezor import loop

    slide = await ui.backlight_slide(ui.BACKLIGHT_NORMAL, delay=0)
    loop.schedule(slide)


@ui.layout
async def ui_text(text, tm=None) -> None:
    from trezor import loop

    text.render()

    if tm is not None:
        await loop.sleep(tm)


async def simple_text(text, tm=None) -> None:
    from trezor import loop
    from trezor.ui import display

    display.clear()
    text.render()

    if tm is not None:
        await loop.sleep(tm)


def format_amount(value):
    return "%f XMR" % (value / 1000000000000)


def split_address(address):
    return chunks(address, 16)
